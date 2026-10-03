import json
import os
from pathlib import Path

import pytest

import app.main as main
import app.nmap_base_analysis as nmap_base
from app.artifacts import register_artifact_file
from app.database import connect_database
from app.identity_overrides import set_os_override
from app.poc import init_poc_storage
from app.storage_health import backfill_storage


XML_A = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
</ports></host><runstats><finished time="110" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''

XML_B = XML_A.replace(b"443", b"444")


def configure_main(monkeypatch, db: Path, runs_root: Path) -> None:
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "run_directory", lambda run_id: runs_root / run_id)


def set_run_status(db: Path, manifest: dict, status: str) -> None:
    manifest["status"] = status
    with connect_database(db) as connection:
        connection.execute(
            "UPDATE scan_runs SET status = ?, manifest_json = ? WHERE run_id = ?",
            (status, json.dumps(manifest, sort_keys=True), manifest["run_id"]),
        )


def create_run(
    db: Path,
    runs_root: Path,
    run_id: str,
    content: bytes = XML_A,
    *,
    registered: bool = True,
    registration_marker: bool | None = None,
    partial: bool = False,
) -> tuple[dict, dict | None]:
    init_poc_storage(db)
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "scan.xml").write_bytes(content)
    manifest = {
        "run_id": run_id,
        "created_at": "2026-10-03T00:00:00+00:00",
        "status": "completed",
        "operator": "analyst",
        "partial_results": partial,
        "execution_note": "UDP phase did not complete." if partial else "",
    }
    with connect_database(db) as connection:
        connection.execute(
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, manifest["created_at"], manifest["status"], "analyst", "test",
                "host", "eth0", "profile", json.dumps(manifest, sort_keys=True),
            ),
        )
    artifact = None
    if registered:
        artifact = register_artifact_file(
            db_path=db,
            source_path=run_dir / "scan.xml",
            source_kind="nmap_scan",
            source_ref=run_id,
            original_filename="scan.xml",
            actor="analyst",
            observation_key=f"nmap_scan:{run_id}:scan.xml",
        )
    marker = registered if registration_marker is None else registration_marker
    if marker:
        digest = artifact["sha256"] if artifact else "missing"
        manifest["artifact_registry"] = {
            "status": "complete",
            "files": [{"filename": "scan.xml", "sha256": digest}],
            "errors": [],
        }
    with connect_database(db) as connection:
        connection.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(manifest, sort_keys=True), run_id),
        )
    (run_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    return manifest, artifact


def test_registered_scan_cold_and_warm_reads_reuse_without_a_warm_write(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    first, _ = create_run(db, runs, "a" * 32)
    second, _ = create_run(db, runs, "b" * 32)
    first["network_scope_id"] = "scope_one"
    second["network_scope_id"] = "scope_two"
    configure_main(monkeypatch, db, runs)
    calls = []

    def parser(content):
        calls.append(content)
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    expected = main.parse_xml(XML_A)
    assert main._run_group_analysis([first]) == expected
    assert main._run_group_analysis([second]) == expected
    assert len(calls) == 1

    writer = connect_database(db)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "UPDATE scan_runs SET status = status WHERE run_id = ?",
            (first["run_id"],),
        )
        assert main._run_group_analysis([first]) == expected
    finally:
        writer.rollback()
        writer.close()
    assert len(calls) == 1

    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_analysis_cache'"
        ).fetchone() is None


def test_registered_run_local_copy_must_match_even_with_same_size_and_time(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "c" * 32)
    configure_main(monkeypatch, db, runs)
    path = runs / manifest["run_id"] / "scan.xml"
    original_time = path.stat().st_mtime_ns
    assert len(XML_A) == len(XML_B)
    path.write_bytes(XML_B)
    os.utime(path, ns=(original_time, original_time))

    with pytest.raises(ValueError, match="does not match its registered artifact"):
        main._run_group_analysis([manifest])
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_ambiguous_or_expected_missing_scan_observation_fails_explicitly(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    ambiguous, _ = create_run(db, runs, "d" * 32)
    missing, _ = create_run(
        db, runs, "e" * 32, registered=False, registration_marker=True,
    )
    register_artifact_file(
        db_path=db,
        source_path=runs / ambiguous["run_id"] / "scan.xml",
        source_kind="nmap_scan",
        source_ref=ambiguous["run_id"],
        original_filename="scan.xml",
        actor="other",
        observation_key="second-authoritative-candidate",
    )
    configure_main(monkeypatch, db, runs)

    with pytest.raises(ValueError, match="ambiguous"):
        main._run_group_analysis([ambiguous])
    with pytest.raises(ValueError, match="registered scan.xml observation is missing"):
        main._run_group_analysis([missing])


def test_unregistered_legacy_scan_parses_each_time_and_never_creates_evidence(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "f" * 32, registered=False)
    configure_main(monkeypatch, db, runs)
    calls = []

    def parser(content):
        calls.append(content)
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert len(calls) == 2
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM artifact_observations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0

    backfill = backfill_storage(db)
    assert backfill["completed"] >= 1
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert len(calls) == 3
    with connect_database(db, read_only=True) as connection:
        assert connection.execute(
            """SELECT COUNT(*) FROM artifact_observations
               WHERE source_kind = 'nmap_scan' AND source_ref = ?
                 AND original_filename = 'scan.xml'""",
            (manifest["run_id"],),
        ).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1


def test_protocol_phase_observation_is_never_borrowed_as_aggregate_scan(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "0" * 32, registered=False)
    phase = runs / manifest["run_id"] / "tcp-scan.xml"
    phase.write_bytes(XML_A)
    register_artifact_file(
        db_path=db,
        source_path=phase,
        source_kind="nmap_scan",
        source_ref=manifest["run_id"],
        original_filename="tcp-scan.xml",
        actor="analyst",
        observation_key=f"nmap_scan:{manifest['run_id']}:tcp-scan.xml",
    )
    configure_main(monkeypatch, db, runs)

    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_runtime_parser_version_change_creates_a_new_verified_result(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "1" * 32)
    configure_main(monkeypatch, db, runs)
    calls = []

    def parser(content):
        calls.append(content)
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    main._run_group_analysis([manifest])
    monkeypatch.setattr(nmap_base, "NMAP_BASE_ANALYSIS_VERSION", "nmap-base-analysis:2")
    main._run_group_analysis([manifest])
    assert len(calls) == 2
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 2


def test_run_deleted_during_parse_cannot_publish_or_resurrect_result(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "2" * 32)
    configure_main(monkeypatch, db, runs)

    def parser(content):
        with connect_database(db) as connection:
            connection.execute("DELETE FROM scan_runs WHERE run_id = ?", (manifest["run_id"],))
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    with pytest.raises(ValueError, match="no longer available"):
        main._run_group_analysis([manifest])
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 0


def test_registered_nonterminal_run_is_read_directly_without_reusable_result(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "5" * 32)
    set_run_status(db, manifest, "running")
    configure_main(monkeypatch, db, runs)
    calls = []

    def parser(content):
        calls.append(content)
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert len(calls) == 2
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


@pytest.mark.parametrize("status", ["failed", "cancelled", "timed_out"])
def test_registered_terminal_partial_run_can_use_verified_reuse(
    tmp_path, monkeypatch, status,
):
    db = tmp_path / f"{status}.db"
    runs = tmp_path / f"{status}-scan-runs"
    manifest, _ = create_run(db, runs, status[0] * 32)
    set_run_status(db, manifest, status)
    configure_main(monkeypatch, db, runs)
    calls = []

    def parser(content):
        calls.append(content)
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert main._run_group_analysis([manifest]) == main.parse_xml(XML_A)
    assert len(calls) == 1


def test_status_change_during_parse_prevents_reusable_publication(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    manifest, _ = create_run(db, runs, "6" * 32)
    configure_main(monkeypatch, db, runs)

    def parser(content):
        set_run_status(db, manifest, "running")
        return main.parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    with pytest.raises(ValueError, match="not finalized"):
        main._run_group_analysis([manifest])
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 0


def test_grouping_partial_warning_and_fresh_override_remain_outside_reuse(
    tmp_path, monkeypatch,
):
    db = tmp_path / "nct.db"
    runs = tmp_path / "scan-runs"
    first, _ = create_run(db, runs, "3" * 32, XML_A)
    second, _ = create_run(db, runs, "4" * 32, XML_B, registered=False, partial=True)
    configure_main(monkeypatch, db, runs)
    expected = main.merge_analyses([main.parse_xml(XML_A), main.parse_xml(XML_B)])
    expected["warnings"] = list(dict.fromkeys([
        *(expected.get("warnings") or []),
        "Partial scan evidence: UDP phase did not complete.",
    ]))
    expected.setdefault("coverage", {})["partial_results"] = True
    assert main._run_group_analysis([first, second]) == expected

    main._run_group_analysis([first])
    set_os_override(
        db,
        ip="192.0.2.10",
        os_name="Operator Confirmed OS",
        analyst="analyst",
        reason="Console confirmation",
    )
    refreshed = main._run_group_analysis_with_overrides([first])
    assert refreshed["hosts"][0]["effective_os"] == "Operator Confirmed OS"
