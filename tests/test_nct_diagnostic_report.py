from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "nct-diagnostic-report.py"
WRAPPER_PATH = ROOT / "scripts" / "nct-diagnostic-report.sh"


def load_helper():
    spec = importlib.util.spec_from_file_location("nct_diagnostic_report", HELPER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_database(root: Path) -> Path:
    path = root / "analyzer.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            PRAGMA foreign_keys=ON;
            CREATE TABLE analyst_users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
            CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, status TEXT, target TEXT);
            CREATE TABLE scan_schedules (id INTEGER PRIMARY KEY);
            CREATE TABLE saved_networks (id INTEGER PRIMARY KEY);
            CREATE TABLE network_scopes (id INTEGER PRIMARY KEY);
            CREATE TABLE artifact_registry (id INTEGER PRIMARY KEY);
            INSERT INTO analyst_users(username, password_hash) VALUES ('admin', 'SUPER-SECRET-HASH');
            INSERT INTO scan_runs(status, target) VALUES ('running', '10.50.15.0/24');
            INSERT INTO scan_runs(status, target) VALUES ('complete', '10.60.0.0/16');
            """
        )
    return path


def test_database_report_is_counts_only_and_does_not_expose_rows(tmp_path: Path):
    helper = load_helper()
    database = create_database(tmp_path)
    before = sha256(database)

    report = helper.database_report(tmp_path)

    assert report["status"] == "ok"
    assert report["summary_counts"]["analyst_accounts"] == 1
    assert report["summary_counts"]["scan_runs"] == 2
    assert report["unfinished_work"] == [
        {"table": "scan_runs", "state": "running", "count": 1}
    ]
    serialized = json.dumps(report)
    assert "SUPER-SECRET-HASH" not in serialized
    assert "10.50.15.0/24" not in serialized
    assert sha256(database) == before


@pytest.mark.parametrize("kind", ["missing", "corrupt"])
def test_database_report_marks_unavailable_database_not_checked(tmp_path: Path, kind: str):
    helper = load_helper()
    if kind == "corrupt":
        (tmp_path / "analyzer.db").write_bytes(b"not a sqlite database")

    report = helper.database_report(tmp_path)

    assert report["status"] == "not_checked"
    assert report["unfinished_work"] is None
    assert report["reason"]


def test_database_report_reads_committed_wal_without_changing_database_or_wal(tmp_path: Path):
    helper = load_helper()
    database = tmp_path / "analyzer.db"
    writer = sqlite3.connect(database)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, status TEXT)")
    writer.execute("INSERT INTO scan_runs(status) VALUES ('running')")
    writer.commit()
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT INTO scan_runs(status) VALUES ('queued')")
    wal = tmp_path / "analyzer.db-wal"
    before = {path.name: sha256(path) for path in (database, wal)}

    try:
        report = helper.database_report(tmp_path)
        after = {path.name: sha256(path) for path in (database, wal)}
    finally:
        writer.rollback()
        writer.close()

    assert report["status"] == "ok"
    assert report["summary_counts"]["scan_runs"] == 1
    assert report["unfinished_work"] == [
        {"table": "scan_runs", "state": "running", "count": 1}
    ]
    assert after == before


def test_database_report_uses_one_snapshot_when_writer_commits_between_queries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    helper = load_helper()
    database = tmp_path / "analyzer.db"
    writer = sqlite3.connect(database)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, status TEXT)")
    writer.execute("INSERT INTO scan_runs(status) VALUES ('running')")
    writer.commit()
    original_tables = helper._tables
    committed = False

    def tables_then_commit(connection: sqlite3.Connection) -> set[str]:
        nonlocal committed
        tables = original_tables(connection)
        writer.execute("INSERT INTO scan_runs(status) VALUES ('queued')")
        writer.commit()
        committed = True
        return tables

    monkeypatch.setattr(helper, "_tables", tables_then_commit)
    try:
        report = helper.database_report(tmp_path)
    finally:
        writer.close()

    assert committed is True
    assert report["summary_counts"]["scan_runs"] == 1
    assert report["unfinished_work"] == [
        {"table": "scan_runs", "state": "running", "count": 1}
    ]


def test_stable_database_snapshot_never_opens_or_changes_retained_database(tmp_path: Path):
    helper = load_helper()
    database = create_database(tmp_path)
    before = sha256(database)
    snapshot_root = tmp_path / "probe" / "database-snapshot"

    snapshot, reason = helper.stable_database_snapshot(tmp_path, snapshot_root)

    assert reason is None
    assert snapshot == snapshot_root
    assert sha256(database) == before
    assert sha256(snapshot_root / "analyzer.db") == before
    assert helper.database_report(snapshot_root)["status"] == "ok"


def test_database_snapshot_is_rejected_when_source_changes_during_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    helper = load_helper()
    database = create_database(tmp_path)
    original_sha256 = helper._sha256
    source_hash_calls = 0

    def hash_then_change(path: Path) -> str:
        nonlocal source_hash_calls
        digest = original_sha256(path)
        if path == database:
            source_hash_calls += 1
            if source_hash_calls == 1:
                with sqlite3.connect(database) as connection:
                    connection.execute("INSERT INTO scan_runs(status, target) VALUES ('queued', 'safe-test')")
        return digest

    monkeypatch.setattr(helper, "_sha256", hash_then_change)
    snapshot, reason = helper.stable_database_snapshot(
        tmp_path, tmp_path / "probe" / "database-snapshot"
    )

    assert snapshot is None
    assert reason == "database files changed while the read-only snapshot was copied"


def test_foreign_key_results_are_bounded(tmp_path: Path):
    helper = load_helper()
    database = tmp_path / "analyzer.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE parent (id INTEGER PRIMARY KEY);
            CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));
            """
        )
        connection.executemany(
            "INSERT INTO child(parent_id) VALUES (?)", ((index,) for index in range(1, 1_050))
        )

    report = helper.database_report(tmp_path)

    assert report["status"] == "needs_attention"
    assert report["foreign_key_errors"] == 1_000
    assert report["foreign_key_errors_truncated"] is True


def test_log_summary_retains_only_counts_even_for_hard_to_redact_secrets():
    helper = load_helper()
    text = "\n".join(
        [f"line {index}" for index in range(450)]
        + [
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "password=SecretValue",
            "https://admin:SecretPass@example.invalid/path",
            "token: secret-token-value",
            '{"password": "SYNTHETIC_SECRET"}',
            "password=alpha beta gamma",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN PRIVATE KEY----- hidden -----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY----- truncated-secret-material",
            "ERROR database is locked while scan queue restarted",
        ]
    )

    summary = helper.summarize_logs(text)
    result = json.dumps(summary)

    assert summary["lines_observed"] == helper.MAX_LOG_LINES
    assert summary["raw_lines_retained"] is False
    assert summary["sensitive_lines_observed"] >= 6
    assert summary["signal_counts"]["error"] == 1
    assert summary["signal_counts"]["database_locked"] == 1
    assert summary["signal_counts"]["scan_queue"] == 1
    for secret in (
        "abcdefghijklmnopqrstuvwxyz",
        "SecretValue",
        "SecretPass",
        "secret-token-value",
        "SYNTHETIC_SECRET",
        "alpha beta gamma",
        "hidden",
        "truncated-secret-material",
        "normal status",
    ):
        assert secret not in result


def test_query_deadline_interrupts_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    helper = load_helper()
    database = tmp_path / "analyzer.db"
    with sqlite3.connect(database) as connection:
        monkeypatch.setattr(helper, "SQL_DEADLINE_SECONDS", -1.0)
        with pytest.raises(sqlite3.OperationalError, match="interrupt"):
            helper._bounded_query(
                connection,
                "WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<1000000) "
                "SELECT sum(n) FROM x",
            )


def test_final_report_is_private_sanitized_and_detects_state_change(tmp_path: Path):
    create_database(tmp_path)
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "container-before.env").write_text(
        "CONTAINER_ID=one\nSTATE=running\nHEALTH=healthy\nRESTART_COUNT=0\nIMAGE_ID=sha256:test\n",
        encoding="utf-8",
    )
    (probe / "container-after.env").write_text(
        "CONTAINER_ID=one\nSTATE=restarting\nHEALTH=unhealthy\nRESTART_COUNT=1\nIMAGE_ID=sha256:test\n",
        encoding="utf-8",
    )
    (probe / "mounts.json").write_text(
        json.dumps([{"Type": "bind", "Source": "/safe/data", "Destination": "/data", "RW": True}]),
        encoding="utf-8",
    )
    (probe / "ports.json").write_text(
        json.dumps({"8445/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8445"}]}),
        encoding="utf-8",
    )
    (probe / "logs.raw").write_text("password=do-not-keep\nnormal status\n", encoding="utf-8")
    output = tmp_path / "reports" / "report.txt"

    completed = subprocess.run(
        [
            sys.executable,
            str(HELPER_PATH),
            "--probe-dir",
            str(probe),
            "--data-root",
            str(tmp_path),
            "--output",
            str(output),
            "--container",
            "nct",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    result = json.loads(completed.stdout)

    assert result["completeness"] == "partial"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.with_suffix(".json").stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(str(output) + ".sha256").stat().st_mode) == 0o600
    report_text = output.read_text(encoding="utf-8")
    assert "state_changed_during_report\": true" in report_text
    assert "do-not-keep" not in report_text
    assert "normal status" not in report_text
    assert '"raw_lines_retained": false' in report_text
    assert "database check was unavailable" not in result["next_step"]


def _write_fake_docker(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _written_reports(output: Path) -> list[Path]:
    return list(output.glob("nct-diagnostic-*/report.txt"))


def test_wrapper_uses_terminal_only_partial_when_docker_is_denied(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_docker(fake_bin / "docker", "exit 1\n")
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    assert not output.exists()
    assert "Docker access was denied" in completed.stdout
    assert "Report completeness: partial" in completed.stdout
    assert "Next step:" in completed.stdout
    assert "Nothing was restarted" in completed.stdout


def test_wrapper_lists_candidates_without_guessing(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_docker(
        fake_bin / "docker",
        """case "$1" in
info) exit 0 ;;
version) echo 'Server fake / API fake'; exit 0 ;;
inspect) exit 1 ;;
ps) printf '%s\\n' 'nct-old' 'nct-candidate'; exit 0 ;;
esac
exit 1
""",
    )
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    assert not output.exists()
    assert "no selection was guessed" in completed.stdout
    assert "nct-old" in completed.stdout and "nct-candidate" in completed.stdout
    assert "Report completeness: partial" in completed.stdout


def test_wrapper_rejects_relative_and_symlink_output_paths(tmp_path: Path):
    relative = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", "relative/reports"],
        text=True,
        capture_output=True,
    )
    assert relative.returncode == 2
    assert "absolute path" in relative.stderr

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    linked = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(link)],
        text=True,
        capture_output=True,
    )
    assert linked.returncode == 2
    assert "symbolic-link" in linked.stderr
    assert list(real.iterdir()) == []


def test_wrapper_keeps_existing_output_root_permissions_and_uses_private_child(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_docker(fake_bin / "docker", _docker_probe_fake("missing_image"))
    output = tmp_path / "reports"
    output.mkdir(mode=0o755)
    output.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    assert stat.S_IMODE(output.stat().st_mode) == 0o755
    report = _written_reports(output)[0]
    assert stat.S_IMODE(report.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert stat.S_IMODE(report.with_name("report.json").stat().st_mode) == 0o600


def test_wrapper_rejects_data_overlap_before_creating_output(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    body = _docker_probe_fake("bind_overlap").replace(
        "*'.Type'*) echo volume ;;", "*'.Type'*) echo bind ;;"
    ).replace(
        "*'.Source'*) echo /fake/data ;;", f"*'.Source'*) echo {data} ;;"
    )
    _write_fake_docker(fake_bin / "docker", body)
    output = data / "diagnostics"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    assert not output.exists()
    assert "outside NCT retained data" in completed.stdout


def test_wrapper_rejects_named_volume_backing_path_overlap_before_creating_output(
    tmp_path: Path,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    volume_data = tmp_path / "volume-data"
    volume_data.mkdir()
    body = _docker_probe_fake("volume_overlap").replace(
        "*'.Source'*) echo /fake/data ;;", f"*'.Source'*) echo {volume_data} ;;"
    )
    _write_fake_docker(fake_bin / "docker", body)
    output = volume_data / "diagnostics"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    assert not output.exists()
    assert "outside NCT retained data" in completed.stdout
    assert "Report completeness: partial" in completed.stdout
    assert "Next step:" in completed.stdout


@pytest.mark.parametrize(
    ("mount_field", "message"),
    [
        ("Type", "data-storage type"),
        ("Source", "data-storage location"),
        ("Name", "data-storage name"),
    ],
)
def test_wrapper_reports_late_mount_detail_timeout_without_silent_exit(
    tmp_path: Path, mount_field: str, message: str
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    body = _docker_probe_fake("mount_detail_timeout").replace(
        f"*'.{mount_field}'*) "
        + ({"Type": "echo volume", "Source": "echo /fake/data", "Name": "echo fake-volume"}[mount_field])
        + " ;;",
        f"*'.{mount_field}'*) exit 1 ;;",
    )
    _write_fake_docker(fake_bin / "docker", body)
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    assert not output.exists()
    assert message in completed.stdout
    assert "Report completeness: partial" in completed.stdout
    assert "Next step:" in completed.stdout


def test_wrapper_bounds_stalled_docker_and_leaves_no_report_or_target_mutation(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.txt"
    _write_fake_docker(
        fake_bin / "docker",
        f"printf '%s\\n' \"$*\" >> {calls}\ncase \"$1\" in info) sleep 30 ;; esac\nexit 1\n",
    )
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["NCT_DIAGNOSTIC_DOCKER_PROBE_TIMEOUT"] = "1"
    started = time.monotonic()

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
        timeout=8,
    )
    elapsed = time.monotonic() - started

    assert completed.returncode == 1
    assert elapsed < 5
    assert not output.exists()
    assert calls.read_text(encoding="utf-8").splitlines() == ["info"]
    assert "did not respond within 1 seconds" in completed.stdout


def test_wrapper_removes_named_helpers_after_helper_timeouts(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.txt"
    body = _docker_probe_fake("helper_timeout").replace(
        "mode=helper_timeout",
        f"mode=helper_timeout\nprintf '%s\\n' \"$*\" >> {calls}",
    ).replace("image) exit 1 ;;", "image) exit 0 ;;").replace(
        "ps) exit 0 ;;", "run) sleep 30; exit 1 ;;\nrm) exit 0 ;;\nps) exit 0 ;;"
    )
    _write_fake_docker(fake_bin / "docker", body)
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["NCT_DIAGNOSTIC_DOCKER_PROBE_TIMEOUT"] = "2"
    environment["NCT_DIAGNOSTIC_DOCKER_HELPER_TIMEOUT"] = "1"
    started = time.monotonic()

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
        timeout=10,
    )
    elapsed = time.monotonic() - started

    assert completed.returncode == 1
    assert elapsed < 7
    report = _written_reports(output)[0]
    assert "could not finish the private report" in report.read_text(encoding="utf-8")
    logged_calls = calls.read_text(encoding="utf-8").splitlines()
    helper_runs = [line for line in logged_calls if line.startswith("run --name nct-diagnostic-")]
    helper_removals = [line for line in logged_calls if line.startswith("rm -f nct-diagnostic-")]
    assert len(helper_runs) == 2
    assert len(helper_removals) == 2
    assert any("nct-diagnostic-db-" in line for line in helper_removals)
    assert any("nct-diagnostic-render-" in line for line in helper_removals)
    assert "Report completeness: partial" in completed.stdout
    assert "Next step:" in completed.stdout


def test_wrapper_retains_helper_identity_and_probe_when_removal_cannot_be_verified(
    tmp_path: Path,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.txt"
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    body = _docker_probe_fake("cleanup_failure").replace(
        "mode=cleanup_failure",
        f"mode=cleanup_failure\nprintf '%s\\n' \"$*\" >> {calls}",
    ).replace("image) exit 1 ;;", "image) exit 0 ;;").replace(
        "ps) exit 0 ;;",
        "run) exit 1 ;;\n"
        "rm) exit 1 ;;\n"
        "ps) case \"$*\" in *'name=^/nct-diagnostic-'*) echo still-present ;; esac; exit 0 ;;",
    )
    _write_fake_docker(fake_bin / "docker", body)
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["TMPDIR"] = str(private_temp)

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    report = _written_reports(output)[0]
    report_text = report.read_text(encoding="utf-8")
    assert "Cleanup could not be verified for diagnostic helper" in report_text
    assert "nct-diagnostic-db-" in report_text
    assert "Private probe workspace retained at:" in report_text
    assert "remove only that helper if present" in report_text
    retained_probes = list(private_temp.glob("nct-diagnostic.*"))
    assert len(retained_probes) == 1
    assert retained_probes[0].is_dir()
    assert "cleanup remains unverified" in completed.stderr
    logged_calls = calls.read_text(encoding="utf-8").splitlines()
    assert sum(line.startswith("rm -f nct-diagnostic-db-") for line in logged_calls) >= 2


def test_wrapper_keeps_reported_probe_after_exit_retry_confirms_helper_absent(
    tmp_path: Path,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.txt"
    removal_count = tmp_path / "removal-count.txt"
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    body = _docker_probe_fake("transient_cleanup_failure").replace(
        "mode=transient_cleanup_failure",
        f"mode=transient_cleanup_failure\nprintf '%s\\n' \"$*\" >> {calls}",
    ).replace("image) exit 1 ;;", "image) exit 0 ;;").replace(
        "ps) exit 0 ;;",
        "run) exit 1 ;;\n"
        "rm) count=0; [ ! -f '"
        + str(removal_count)
        + "' ] || count=$(cat '"
        + str(removal_count)
        + "'); count=$((count + 1)); echo \"$count\" > '"
        + str(removal_count)
        + "'; [ \"$count\" -ne 1 ] ;;\n"
        "ps) [ ! -f '"
        + str(removal_count)
        + "' ] || [ \"$(cat '"
        + str(removal_count)
        + "')\" -ne 1 ] || echo still-present; exit 0 ;;",
    )
    _write_fake_docker(fake_bin / "docker", body)
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["TMPDIR"] = str(private_temp)

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    report = _written_reports(output)[0]
    report_text = report.read_text(encoding="utf-8")
    assert "Private probe workspace retained at:" in report_text
    assert "confirm whether helper 'nct-diagnostic-db-" in report_text
    assert "remove only that helper if present" in report_text
    retained_probes = list(private_temp.glob("nct-diagnostic.*"))
    assert len(retained_probes) == 1
    assert retained_probes[0].is_dir()
    assert "helper absence was confirmed during final cleanup" in completed.stderr
    assert removal_count.read_text(encoding="utf-8").strip() == "2"


def _docker_probe_fake(mode: str) -> str:
    return f"""mode={mode}
case "$1" in
info) exit 0 ;;
version) echo 'Server fake / API fake'; exit 0 ;;
logs) echo 'bounded log'; exit 0 ;;
image) exit 1 ;;
inspect)
  [ "$2" = "--format" ] || exit 0
  template=$3
  case "$template" in
    *CONTAINER_ID*) printf '%s\\n' 'CONTAINER_ID=test-id' 'STATE=stopped' 'HEALTH=none' 'RESTART_COUNT=0' 'EXIT_CODE=0' 'OOM_KILLED=false' 'STARTED_AT=never' 'FINISHED_AT=now' 'IMAGE_ID=sha256:missing' ;;
    *'.Mounts}}') echo '[]' ;;
    *PortBindings*) echo '{{}}' ;;
    *RestartPolicy*) echo '{{"Name":"no"}}' ;;
    *println*) if [ "$mode" = ambiguous ]; then printf 'x\\nx\\n'; else printf 'x\\n'; fi ;;
    *'.Type'*) echo volume ;;
    *'.Source'*) echo /fake/data ;;
    *'.Name'*) echo fake-volume ;;
  esac
  exit 0
  ;;
ps) exit 0 ;;
esac
exit 1
"""


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("ambiguous", "exactly one is required"),
        ("missing_image", "exact image used by the saved container is no longer available"),
    ],
)
def test_wrapper_reports_ambiguous_data_or_missing_exact_image(
    tmp_path: Path, mode: str, message: str
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_docker(fake_bin / "docker", _docker_probe_fake(mode))
    output = tmp_path / "reports"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

    completed = subprocess.run(
        ["sh", str(WRAPPER_PATH), "--output-dir", str(output)],
        text=True,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 1
    if mode == "ambiguous":
        assert not output.exists()
        assert message in completed.stdout
    else:
        report = _written_reports(output)[0]
        assert message in report.read_text(encoding="utf-8")
        assert report.with_name("report.json").exists()
        assert Path(str(report) + ".sha256").exists()
        assert "Report completeness: partial" in completed.stdout
        assert "Next step:" in completed.stdout


def test_wrapper_does_not_contain_container_or_storage_mutations():
    content = WRAPPER_PATH.read_text(encoding="utf-8")
    for command in (
        "docker restart",
        "docker stop",
        "docker start",
        "docker update",
        "docker volume rm",
        "PRAGMA wal_checkpoint",
        "VACUUM",
    ):
        assert command not in content
    assert "--network none" in content
    assert "--read-only" in content
    assert "--cap-drop ALL" in content
    assert "--security-opt no-new-privileges" in content
    assert "--security-opt label=disable" in content
    assert "docker_probe()" in content
    assert "docker_helper()" in content
    assert "timeout -k" in content
    assert '--name "$DB_HELPER_NAME"' in content
    assert '--name "$RENDER_HELPER_NAME"' in content
    assert "remove_and_confirm_helper()" in content
    assert 'remove_and_confirm_helper "$DB_HELPER_NAME"' in content
    assert 'remove_and_confirm_helper "$RENDER_HELPER_NAME"' in content
    assert "Private probe workspace retained at:" in content
    assert "PRESERVE_PROBE=1" in content
    assert "query_only=ON" in HELPER_PATH.read_text(encoding="utf-8")
    assert 'connection.execute("BEGIN")' in HELPER_PATH.read_text(encoding="utf-8")
