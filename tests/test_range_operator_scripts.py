import hashlib
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
START_SCRIPTS = (
    SCRIPTS / "nct-start-legacy.sh",
    SCRIPTS / "nct-start-docker.sh",
    SCRIPTS / "nct-start-compose.sh",
)
PACKAGE_SCRIPTS_README = ROOT / "docs" / "RANGE_PACKAGE_SCRIPTS_README.md"


def _embedded_python(name: str) -> str:
    content = (SCRIPTS / "nct-upgrade.sh").read_text(encoding="utf-8")
    marker = f"{name}='\n"
    return content.split(marker, 1)[1].split("\n'\n", 1)[0]


def _run_embedded_python(name: str, data_root: Path) -> None:
    code = _embedded_python(name).replace("/data", data_root.as_posix())
    exec(compile(code, f"<{name}>", "exec"), {})


def test_range_start_scripts_share_the_operator_facing_defaults():
    for script in START_SCRIPTS:
        content = script.read_text(encoding="utf-8")
        assert 'HOST_PORT="${NCT_HTTPS_PORT:-8445}"' in content
        assert "/root/NCT-Air-Gapped-Range-Deployment" in content
        assert 'PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"' in content
        assert 'DATA_DIR="$PERSIST_ROOT/data"' in content
        assert ':Z"' in content or 'export NCT_DATA_DIR="$DATA_DIR"' in content
        assert "nmap-terrain-analyzer" not in content
        assert "clutts" not in content.lower()
        assert 'docker inspect "$CONTAINER"' in content
        assert 'sh "$WORKDIR/scripts/nct-set-admin.sh" "$ADMIN_USER"' in content
        assert 'rm -f "$BOOTSTRAP_PASSWORD"' in content
        assert "Preserving $account_count existing NCT account(s)" in content
        assert "verify_archive_checksum" in content
        assert "expected_checksum" in content
        assert "actual_checksum" in content
        assert "curl --connect-timeout 2 --max-time 5" in content


def test_legacy_workaround_is_not_applied_to_the_modern_docker_path():
    legacy = (SCRIPTS / "nct-start-legacy.sh").read_text(encoding="utf-8")
    modern = (SCRIPTS / "nct-start-docker.sh").read_text(encoding="utf-8")
    assert "--security-opt seccomp=unconfined" in legacy
    assert "--security-opt seccomp=unconfined" not in modern


def test_compose_start_path_requires_the_plugin_and_range_definition():
    script = (SCRIPTS / "nct-start-compose.sh").read_text(encoding="utf-8")
    compose = (ROOT / "compose.range.yaml").read_text(encoding="utf-8")
    assert "docker compose version" in script
    assert 'COMPOSE_FILE="$WORKDIR/compose.range.yaml"' in script
    assert '"${NCT_BIND_ADDRESS}:${NCT_HTTPS_PORT}:8445"' in compose
    assert "${NCT_DATA_DIR}:/data:Z" in compose
    assert "name: nct-data" not in compose
    assert "seccomp=unconfined" not in compose


def test_admin_helper_changes_nct_accounts_without_a_fixed_username():
    content = (SCRIPTS / "nct-set-admin.sh").read_text(encoding="utf-8")
    assert "clutts" not in content.lower()
    assert "useradd" not in content
    assert "passwd " not in content
    assert "from app.auth import create_user" in content
    assert "reset_user_password" in content
    assert "set_user_disabled" in content
    assert 'docker exec -i "$container"' in content
    assert "All previous sessions" in content


def test_quick_start_selects_one_of_the_three_launch_paths():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    assert "docker version" in content
    assert "docker compose version" in content
    assert "PORT_8445_FREE" in content
    assert "curl --connect-timeout 2 --max-time 5 -k https://RANGE_IP:8445/health" in content
    for script in START_SCRIPTS:
        assert script.name in content
    assert "nct-set-admin.sh" in content
    assert "nct-migrate-data.sh" in content
    assert "/var/lib/nct/data" in content
    assert "nmap-terrain-analyzer" not in content
    assert "API **1.41 or newer**" in content
    assert "API **1.39 or 1.40**" in content
    assert "older than **1.39**" in content


def test_quick_start_keeps_an_existing_package_folder_separate():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )

    assert 'if [ -e "$package_dir/NCT-Air-Gapped-Range-Deployment" ]; then' in content
    assert 'mkdir -m 0700 "$staging_dir"' in content
    assert 'unzip "$package_zip" -d "$staging_dir"' in content
    assert 'export NCT_WORKDIR="$staging_dir/NCT-Air-Gapped-Range-Deployment"' in content
    assert "leave it unchanged" in content
    assert 'sh "$NCT_WORKDIR/scripts/nct-upgrade.sh" RANGE_IP legacy' in content


def test_quick_start_verifies_the_outer_package_before_extraction():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(content.split())

    verify = 'checksum_file="$package_zip.sha256"'
    extract = 'unzip "$package_zip"'
    assert verify in content
    assert content.index(verify) < content.index(extract)
    assert 'package_dir=/root' in content
    assert 'package_zip="$package_dir/NCT-Air-Gapped-Range-Deployment' in content
    assert '(cd "$package_dir" && sha256sum -c "$(basename "$checksum_file")") || exit 1' in content
    assert 'echo "Package SHA-256: $actual_package_sha256"' in content
    assert 'export NCT_PACKAGE_SHA256="$actual_package_sha256"' in content
    assert "A missing" in content
    assert "stops installation before extraction" in content
    assert "0.16.0-range-test-20261025-phase5-r1" in content
    assert "b908834cb60327a640e9987fddff036c4df9fb75" in content
    assert "version-5 installation must first" in content
    assert "0.16.0-20261019-phase4-r5.zip" in content
    assert "That bridge and its adjacent checksum are not included" in normalized
    assert "docker restart nct || exit 1" in content
    assert "NCT did not become healthy after restart" in content
    assert '"build_id":"0.16.0-range-test-20261025-phase5-r1' in content


def test_unhealthy_source_recovery_is_fail_closed_and_fully_verified():
    script = (SCRIPTS / "nct-recover-unhealthy-upgrade.sh").read_text(
        encoding="utf-8"
    )
    guide = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized_guide = " ".join(guide.split())

    assert "NCT_PACKAGE_SHA256" in script
    assert "sha256sum -c PACKAGE-MANIFEST.sha256" in script
    assert 'ARCHIVE_CHECKSUM="$ARCHIVE.sha256"' in script
    assert "?mode=ro&immutable=1" in script
    assert "no_other_writer" in script
    assert "wal_checkpoint(TRUNCATE)" in script
    assert script.index("wal_checkpoint(TRUNCATE)") < script.rindex("active_check")
    assert "nct-schema-preflight.py" in script
    assert "--required-source-version 6" in script
    assert "report.get(\"database_sha256\")" in script
    assert "recovery-backup-verify" in script
    assert "cmp -s \"$before\" \"$verify_inventory\"" in script
    assert "restore_on_failure" in script
    assert "failed-recovery-data" in script
    assert "The incompatible old image remains stopped" in script
    assert "artifact_registry" in script
    assert "Stored record count decreased" in script
    assert "candidate_account_count" in script
    assert "docker restart \"$CONTAINER\"" in script
    final_restart = script.split('docker restart "$CONTAINER"', 1)[1]
    assert '"status":"ok"' in final_restart
    assert "$EXPECTED_BUILD_ID" in final_restart
    assert "$EXPECTED_BUILD_COMMIT" in final_restart
    assert "restarted replacement build ID is wrong" in final_restart
    assert "restarted replacement build commit is wrong" in final_restart
    assert "isolate_failed_candidate" in script
    assert "No backup was extracted over the existing data" in script
    assert "recovery-upgrade-$timestamp.receipt" in script
    assert "nct-recover-unhealthy-upgrade.sh" in guide
    assert "never starts the old image against replacement-written data" in normalized_guide


@pytest.mark.parametrize(
    ("saved_ports", "expected_status", "expected_output"),
    (
        ("8445", 0, "8445"),
        ("", 1, ""),
        ("8445\n9445", 1, ""),
        ("not-a-port", 1, ""),
        ("0", 1, ""),
        ("65536", 1, ""),
    ),
)
def test_recovery_reads_one_valid_https_port_from_stopped_container_configuration(
    tmp_path, saved_ports, expected_status, expected_output
):
    script = (SCRIPTS / "nct-recover-unhealthy-upgrade.sh").read_text(
        encoding="utf-8"
    )
    body = script.split("# SAVED_HTTPS_PORT_FUNCTION_START\n", 1)[1].split(
        "# SAVED_HTTPS_PORT_FUNCTION_END", 1
    )[0]
    harness = f"""
set -eu
SAVED_PORTS={saved_ports!r}
docker() {{
    [ "$1" = inspect ] || return 1
    printf '%s\n' "$SAVED_PORTS"
}}
{body}
saved_https_host_port nct
"""
    result = subprocess.run(
        ["sh", "-c", harness],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == expected_status
    assert result.stdout.strip() == expected_output


def test_recovery_uses_saved_port_bindings_before_any_package_load_or_data_action():
    script = (SCRIPTS / "nct-recover-unhealthy-upgrade.sh").read_text(
        encoding="utf-8"
    )

    assert '.HostConfig.PortBindings "8445/tcp"' in script
    assert 'original_host_port=$(saved_https_host_port "$CONTAINER")' in script
    assert script.index('original_host_port=$(saved_https_host_port "$CONTAINER")') < script.index(
        'say "Disabling the failed restart loop'
    )
    assert script.index('original_host_port=$(saved_https_host_port "$CONTAINER")') < script.index(
        'docker load -i "$ARCHIVE"'
    )
    assert 'candidate_host_port=$(saved_https_host_port "$CONTAINER")' in script


def test_range_data_checker_reads_live_wal_and_uses_immutable_only_when_requested(
    tmp_path, capsys
):
    helpers = runpy.run_path(str(SCRIPTS / "nct-range-data-check.py"))
    db_path = tmp_path / "analyzer.db"
    writer = sqlite3.connect(db_path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE scan_runs (status TEXT)")
    writer.commit()
    writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    writer.execute("INSERT INTO scan_runs(status) VALUES ('queued')")
    writer.commit()
    try:
        live = helpers["active_work"](tmp_path)
        stopped_only = helpers["active_work"](tmp_path, immutable=True)
        live_snapshot = helpers["snapshot"](tmp_path)
        immutable_snapshot = helpers["snapshot"](tmp_path, immutable=True)
        with pytest.raises(SystemExit) as active_exit:
            _run_embedded_python("active_check_code", tmp_path)
        capsys.readouterr()
        _run_embedded_python("snapshot_code", tmp_path)
        embedded_live_snapshot = json.loads(capsys.readouterr().out)
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        checkpointed_stopped = helpers["active_work"](tmp_path, immutable=True)
    finally:
        writer.close()

    assert live == [{"source": "database", "table": "scan_runs", "count": 1}]
    assert stopped_only == []
    assert live_snapshot["database"]["tables"]["scan_runs"] == 1
    assert immutable_snapshot["database"]["tables"]["scan_runs"] == 0
    assert active_exit.value.code == 42
    assert embedded_live_snapshot["database"]["tables"]["scan_runs"] == 1
    assert checkpointed_stopped == [
        {"source": "database", "table": "scan_runs", "count": 1}
    ]


@pytest.mark.parametrize("failure_step", ("stop", "rename", "move"))
def test_recovery_never_extracts_over_data_when_candidate_isolation_fails(
    tmp_path, failure_step
):
    script = (SCRIPTS / "nct-recover-unhealthy-upgrade.sh").read_text(
        encoding="utf-8"
    )
    body = script.split("# RECOVERY_ISOLATION_FUNCTION_START\n", 1)[1].split(
        "# RECOVERY_ISOLATION_FUNCTION_END", 1
    )[0]
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    failed_data = tmp_path / "failed-data"
    harness = f"""
set -eu
DATA_DIR={data_dir.as_posix()!r}
failed_data={failed_data.as_posix()!r}
CONTAINER=nct
failed_container=nct-failed
FAIL_STEP={failure_step!r}
docker() {{
    command_name=$1
    shift
    case "$command_name:$*" in
        "inspect:nct") return 0 ;;
        "inspect:--format {{{{.State.Running}}}} nct") printf 'false\\n'; return 0 ;;
        "update:--restart=no nct") return 0 ;;
        "stop:nct") [ "$FAIL_STEP" != stop ] ;;
        "rename:nct nct-failed") [ "$FAIL_STEP" != rename ] ;;
        *) return 1 ;;
    esac
}}
mv() {{
    [ "$FAIL_STEP" != move ] || return 1
    command mv "$@"
}}
{body}
if isolate_failed_candidate; then
    exit 90
fi
[ -d "$DATA_DIR" ] || [ -d "$failed_data" ]
printf 'NO_BACKUP_EXTRACTION\\n'
"""
    result = subprocess.run(
        ["sh", "-c", harness],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "NO_BACKUP_EXTRACTION\n"


def test_quick_start_requires_release_specific_scope_handoff_acceptance():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(content.split())

    assert "NCT-Air-Gapped-Range-Deployment-0.16.0-20261025-phase5-r1.zip" in content
    assert "0.16.0-range-test-20261025-phase5-r1" in content
    assert "$NCT_WORKDIR/RELEASE-RECEIPT.txt" in content
    assert "Saved scope handoff needs correction" in content
    assert "Repair saved scope handoff" in content
    assert "Scoped evidence ready · corrected handoff" in content
    assert "does not run Nmap or contact the network" in content
    assert "must remain in the saved history" in normalized
    assert "explicitly approved the Saved Network" in normalized
    assert "Network Scope, scan profile, timing" in normalized
    assert "not yet validated" in content
    assert content.index("RELEASE-RECEIPT.txt") < content.index(
        "Verify this release's Network Scope handoff correction"
    )


def test_quick_start_requires_range_container_resource_acceptance():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(content.split())

    assert "Verify container CPU and memory on this Range host" in content
    assert "Settings → System Health" in content
    assert "at least the second five-second sample" in normalized
    assert "NCT process" in content
    assert "Container CPU row" in content
    assert "Current" in content and "Average" in content and "Maximum" in content
    assert "Time near max" in content
    assert "may correctly be `0 sec`" in normalized
    assert "Unavailable container CPU or memory does not pass" in normalized
    assert "stop acceptance" in content
    assert "Do not change container permissions or mount host files" in normalized


def test_quick_start_stops_on_internal_checksum_failure():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(content.split())

    assert "internal package or image checksum" in normalized
    assert "stop, preserve the package and the displayed output" in normalized
    assert "Never edit or regenerate checksum files on the Range" in normalized
    manifest_check = "sha256sum -c PACKAGE-MANIFEST.sha256 || exit 1"
    assert manifest_check in content
    assert content.index(manifest_check) < content.index("docker version --format")


def test_packaged_scripts_readme_references_only_delivered_operator_material():
    content = PACKAGE_SCRIPTS_README.read_text(encoding="utf-8")
    assert "../AIR-GAPPED-RANGE-QUICKSTART.md" in content
    assert "../docs/AIR_GAPPED_RANGE_QUICKSTART.md" not in content
    assert "qualify_kubernetes_storage.py" not in content
    assert "render_kubernetes_single_replica.py" not in content
    assert "KUBERNETES_SINGLE_REPLICA.md" not in content


def test_volume_migration_is_verified_and_retains_rollback_sources():
    content = (SCRIPTS / "nct-migrate-data.sh").read_text(encoding="utf-8")
    assert 'SOURCE_VOLUME="${NCT_SOURCE_VOLUME:-nct-data}"' in content
    assert 'DATA_DIR="$PERSIST_ROOT/data"' in content
    assert "NCT has active work" in content
    assert "cp -a /source/. /target/" in content
    assert "Source and target inventories do not match" in content
    assert "source_volume_retained=yes" in content
    assert "nct-volume-rollback-$timestamp" in content
    assert 'docker volume rm' not in content
    assert 'rm -rf' not in content


def test_upgrade_script_backs_up_verifies_and_retains_the_previous_container():
    content = (SCRIPTS / "nct-upgrade.sh").read_text(encoding="utf-8")

    assert 'mount_source' in content
    assert '"$mount_source" = "$DATA_DIR"' in content
    assert "NCT has active or unresolved work" in content
    assert 'tar -C "$PERSIST_ROOT" -czf "$backup" data' in content
    assert 'sha256sum "$backup"' in content
    assert "nct-upgrade-rollback-$timestamp" in content
    assert "Stored record count decreased" in content
    assert "Retained file changed or disappeared during upgrade" in content
    assert "Registered artifact identity changed during upgrade" in content
    assert '"artifact_registry": []' in content
    assert 'PRAGMA integrity_check' in content
    assert "start_original_if_needed" in content
    assert 'https://$RANGE_IP:$original_host_port/health' in content
    assert 'docker update --restart=no "$CONTAINER"' in content
    assert 'PRAGMA foreign_key_check' in content
    assert 'SCHEMA_PREFLIGHT="$WORKDIR/scripts/nct-schema-preflight.py"' in content
    assert '"$original_image_id" python -c' in content
    assert 'PRAGMA wal_checkpoint(TRUNCATE)' in content
    assert '"$DATA_DIR:/data:ro,Z"' in content
    assert '"$IMAGE" python /opt/nct-schema-preflight.py --db /data/analyzer.db' in content
    assert '--expected-build-id "$original_build_id"' in content
    assert '--expected-build-commit "$original_build_commit"' in content
    assert "--required-source-version 6" in content
    assert 'schema_preflight_sha256=%s' in content
    assert 'preflight_binding_code' in content
    assert 'schema_preflight=%s' in content
    assert '"$NCT_UPGRADE_PYTHON" "$RUNTIME_CLONE" --original-id "$original_container_id"' in content
    assert 'docker exec "$CONTAINER" python -c "$snapshot_code"' in content
    assert 'snapshot "$before"' in content
    assert content.index('docker stop "$CONTAINER"') < content.index('snapshot "$before"')
    assert content.index('PRAGMA wal_checkpoint(TRUNCATE)') < content.index(
        'python /opt/nct-schema-preflight.py'
    )
    assert content.index('PRAGMA wal_checkpoint(TRUNCATE)') < content.index(
        'check_active sidecar'
    )
    assert content.index('snapshot "$before"') < content.index(
        'schema_preflight_sha256=$(docker run'
    )
    assert content.index('schema_preflight_sha256=$(docker run') < content.index(
        'docker rename "$CONTAINER" "$rollback"'
    )
    assert 'snapshot "$after" container' in content
    assert '"analyzer.db-wal"' in content
    assert '"analyzer.db-shm"' in content
    assert '"analyzer.db-journal"' in content
    assert content.index("trap restore_original EXIT") < content.index(
        'original_stopped=yes\n    docker stop "$CONTAINER"'
    )
    assert 'api_at_least "$server_api" 1.39' in content
    assert 'docker volume rm' not in content
    assert 'rm -rf' not in content
    assert 'docker rm "$CONTAINER"' not in content
    assert "verify_archive_checksum" in content
    assert "expected_checksum" in content
    assert "actual_checksum" in content
    for receipt_field in (
        "rollback_container_id",
        "rollback_image_id",
        "rollback_data_mount_type",
        "rollback_data_mount_source",
        "rollback_host_port",
        "candidate_host_port",
    ):
        assert f"printf '{receipt_field}=%s\\n'" in content
    assert "verify_rollback_identity" in content


def test_packaged_scripts_guide_explains_schema_preflight():
    content = PACKAGE_SCRIPTS_README.read_text(encoding="utf-8")

    assert "stopped-database WAL" in content
    assert "checkpoint" in content
    assert "nct-schema-preflight.py" in content
    assert "data mounted read-only" in content
    assert "restores the earlier container" in content
    assert "## Package contents" in content
    assert "Normal operator entry points" in content
    assert "Main quickstart only" in content
    assert "Internal Python helpers" in content
    assert "Compatibility or administrator tools" in content
    assert "That bridge is not included here" in content


def test_unfinished_scan_recovery_wrapper_is_fail_closed_and_documented():
    content = (SCRIPTS / "nct-reset-unfinished.sh").read_text(encoding="utf-8")
    quickstart = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )

    assert 'trap cleanup EXIT' in content
    assert 'restore_runtime' in content
    assert 'another container has an overlapping NCT data mount' in content
    assert 'cmp -s "$source_inventory" "$restored_inventory"' in content
    assert content.count("LC_ALL=C sort -z") == 2
    assert 'sha256sum "$backup" > "$backup.sha256"' in content
    assert '--plan-digest "$plan_digest"' in content
    assert 'docker_probe update --restart=no "$CONTAINER"' in content
    assert 'timeout -k 5 "$PROBE_TIMEOUT" docker' in content
    assert 'timeout -k 10 "$HELPER_TIMEOUT" docker' in content
    assert '--network none --read-only --cap-drop ALL' in content
    assert '--security-opt no-new-privileges' in content
    assert '--security-opt label=disable' in content
    assert ':Z' not in content
    assert "MaximumRetryCount" in content
    assert "restart policy verification failed" in content
    assert "recovery helper absence could not be proven" in content
    assert "NCT will remain stopped with automatic restart disabled" in content
    assert "volume inspect --format '{{.Mountpoint}}'" in content
    assert '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}' in content
    assert 'docker volume rm' not in content
    assert 'rm -rf' not in content
    assert "nct-reset-unfinished.sh --container nct --apply" in quickstart
    assert "Completed work stays intact" in quickstart
    assert "Resume preserved scans" in PACKAGE_SCRIPTS_README.read_text(encoding="utf-8")


def test_unfinished_scan_recovery_times_out_a_stalled_docker_probe(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text("#!/bin/sh\nsleep 20\n", encoding="utf-8")
    fake_docker.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["NCT_RECOVERY_DOCKER_PROBE_TIMEOUT"] = "1"
    result = subprocess.run(
        ["sh", str(SCRIPTS / "nct-reset-unfinished.sh"), "--output-dir", str(tmp_path / "out")],
        text=True,
        capture_output=True,
        timeout=6,
        env=env,
    )
    assert result.returncode == 2
    assert "NCT container not found" in result.stderr


def _recovery_helper_function_block() -> str:
    content = (SCRIPTS / "nct-reset-unfinished.sh").read_text(encoding="utf-8")
    start = content.index("remove_helper() {")
    end = content.index("cleanup() {", start)
    return content[start:end]


def test_recovery_cleanup_does_not_treat_inventory_timeout_as_absence(tmp_path: Path):
    harness = tmp_path / "cleanup-timeout.sh"
    harness.write_text(
        "#!/bin/sh\nset +e\nhelper=test-helper\ncleanup_blocked=no\n"
        "docker_probe() { return 124; }\n"
        "restore_runtime() { echo RESTORE; }\n"
        + _recovery_helper_function_block()
        + "remove_helper\nstatus=$?\necho STATUS=$status\nexit 0\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["sh", str(harness)], text=True, capture_output=True, timeout=5
    )
    assert result.returncode == 0
    assert "STATUS=1" in result.stdout


def test_failed_helper_removal_keeps_nct_stopped_without_restore(tmp_path: Path):
    harness = tmp_path / "cleanup-removal-failure.sh"
    log = tmp_path / "docker-actions.log"
    harness.write_text(
        f"#!/bin/sh\nset +e\nhelper=test-helper\nCONTAINER=nct\ncleanup_blocked=no\nLOG='{log}'\n"
        "docker_probe() {\n"
        "  case \"$1\" in\n"
        "    ps) echo helper-id; return 0 ;;\n"
        "    rm) return 1 ;;\n"
        "    update) echo HOLD >> \"$LOG\"; return 0 ;;\n"
        "    inspect) case \"$*\" in *RestartPolicy*) echo no:false ;; *) echo false ;; esac; return 0 ;;\n"
        "    stop) echo STOP; return 0 ;;\n"
        "  esac\n"
        "  return 1\n"
        "}\n"
        "restore_runtime() { echo RESTORE; }\n"
        + _recovery_helper_function_block()
        + "finish_and_restore\nstatus=$?\necho STATUS=$status\necho BLOCKED=$cleanup_blocked\nexit 0\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["sh", str(harness)], text=True, capture_output=True, timeout=5
    )
    assert result.returncode == 0
    assert "STATUS=1" in result.stdout
    assert "BLOCKED=yes" in result.stdout
    assert "HOLD" in log.read_text(encoding="utf-8")
    assert "RESTORE" not in result.stdout


def test_upgrade_script_blocks_durable_work_and_restores_before_old_code():
    content = (SCRIPTS / "nct-upgrade.sh").read_text(encoding="utf-8")

    for table in (
        "pipeline_job_attempts",
        "pipeline_admission_intents",
        "device_contact_runs",
        "device_contact_attempts",
        "scan_schedule_occurrences",
        "scan_schedule_chunks",
        "work_leases",
        "artifact_compaction_journal",
    ):
        assert table in content
    assert "NCT has active or unresolved work" in content
    assert 'failed_data="$PERSIST_ROOT/failed-upgrade-data-$timestamp"' in content
    assert 'sha256sum -c "$backup.sha256"' in content
    assert 'tar -C "$PERSIST_ROOT" -xzf "$backup"' in content
    assert 'cmp -s "$before" "$restored_inventory"' in content
    assert content.index('tar -C "$PERSIST_ROOT" -xzf "$backup"') < content.index(
        'docker rename "$rollback" "$CONTAINER"'
    )
    assert "The old application was not started" in content


def test_upgrade_active_check_detects_database_tracked_schedule_work(tmp_path: Path):
    database = sqlite3.connect(tmp_path / "analyzer.db")
    database.execute("CREATE TABLE scan_schedule_occurrences(state TEXT NOT NULL)")
    database.execute("INSERT INTO scan_schedule_occurrences VALUES ('waiting')")
    database.commit()
    database.close()

    helper = runpy.run_path(str(SCRIPTS / "nct-range-data-check.py"))
    assert helper["active_work"](tmp_path) == [
        {"source": "database", "table": "scan_schedule_occurrences", "count": 1}
    ]
    with pytest.raises(SystemExit) as stopped:
        _run_embedded_python("active_check_code", tmp_path)
    assert stopped.value.code == 42


def test_upgrade_active_check_detects_legacy_password_prompt(tmp_path: Path):
    manifest = tmp_path / "device_configs" / "legacy-run" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"status":"waiting_for_password"}', encoding="utf-8")

    helper = runpy.run_path(str(SCRIPTS / "nct-range-data-check.py"))
    assert helper["active_work"](tmp_path) == [
        {"source": "manifest", "path": str(manifest), "state": "waiting_for_password"}
    ]
    with pytest.raises(SystemExit) as stopped:
        _run_embedded_python("active_check_code", tmp_path)
    assert stopped.value.code == 42


def test_upgrade_snapshot_verifies_files_database_and_registered_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    retained = tmp_path / "imports" / "retained.xml"
    retained.parent.mkdir()
    retained.write_bytes(b"<nmaprun />")
    artifact = tmp_path / "artifacts" / "aa" / "evidence.xml"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"evidence")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    database = sqlite3.connect(tmp_path / "analyzer.db")
    database.execute(
        "CREATE TABLE artifact_registry(sha256 TEXT PRIMARY KEY, size_bytes INTEGER, canonical_path TEXT)"
    )
    database.execute(
        "INSERT INTO artifact_registry VALUES (?, ?, ?)",
        (digest, artifact.stat().st_size, str(artifact)),
    )
    database.execute("CREATE TABLE saved_records(record_id TEXT PRIMARY KEY)")
    database.execute("INSERT INTO saved_records VALUES ('record-1')")
    database.commit()
    database.close()

    _run_embedded_python("snapshot_code", tmp_path)
    snapshot = json.loads(capsys.readouterr().out)
    helper = runpy.run_path(str(SCRIPTS / "nct-range-data-check.py"))
    assert helper["snapshot"](tmp_path) == snapshot

    assert snapshot["database"]["integrity"] == "ok"
    assert snapshot["database"]["foreign_key_errors"] == []
    assert snapshot["database"]["tables"]["saved_records"] == 1
    assert snapshot["files"]["imports/retained.xml"]["sha256"] == hashlib.sha256(
        retained.read_bytes()
    ).hexdigest()
    assert snapshot["artifact_registry"] == [
        {"sha256": digest, "size": artifact.stat().st_size}
    ]


def test_upgrade_preflight_report_must_match_inventoried_database(tmp_path: Path):
    report = tmp_path / "schema.json"
    before = tmp_path / "before.json"
    report.write_text(
        json.dumps({"status": "pass", "database_sha256": "a" * 64}),
        encoding="utf-8",
    )
    before.write_text(
        json.dumps({"restore_files": {"analyzer.db": {"sha256": "b" * 64}}}),
        encoding="utf-8",
    )
    code = _embedded_python("preflight_binding_code").replace(
        "/verification", tmp_path.as_posix()
    )

    result = subprocess.run(
        [sys.executable, "-c", code, report.name, before.name],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "does not match" in result.stderr


def test_quick_start_uses_executable_restore_path_and_correct_migration_step():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )

    assert "step 3A migrated an old Docker volume" in content
    assert "Roll back after step 3A migrated" in content
    assert 'sh "$NCT_WORKDIR/scripts/nct-rollback-upgrade.sh" RANGE_IP UPGRADE_RECEIPT' in content
    assert "complete restored file and database inventory" in content
    assert "do not guess" in content
    assert "not contact a device" in content
    assert "not yet validated" in content


def test_manual_upgrade_rollback_restores_and_verifies_before_old_container_starts():
    content = (SCRIPTS / "nct-rollback-upgrade.sh").read_text(encoding="utf-8")

    assert 'DATA_CHECK="$WORKDIR/scripts/nct-range-data-check.py"' in content
    assert "NCT has active or unresolved work" in content
    assert 'docker rename "$CONTAINER" "$failed_container"' in content
    assert 'mv "$DATA_DIR" "$failed_data"' in content
    assert 'sha256sum -c "$checksum"' in content
    assert 'tar -C "$PERSIST_ROOT" -xzf "$backup"' in content
    assert 'cmp -s "$before" "$restored_inventory"' in content
    for receipt_field in (
        "rollback_container_id",
        "rollback_image_id",
        "rollback_data_mount_type",
        "rollback_data_mount_source",
        "rollback_host_port",
    ):
        assert f'{receipt_field}=$(receipt_value {receipt_field})' in content
    assert "does not match the exact container recorded during upgrade" in content
    assert '[ "${#value}" -eq 64 ]' in content
    assert '*[!0-9a-f]*' in content
    assert "does not use the exact image recorded during upgrade" in content
    assert "data mount does not match the upgrade receipt" in content
    assert 'https://$RANGE_IP:$rollback_host_port/health' in content
    assert content.index('cmp -s "$before" "$restored_inventory"') < content.index(
        'docker rename "$rollback" "$CONTAINER"'
    )
    assert 'docker rm' not in content
    assert "The old application was not started" in content
    assert "Docker could not stop the previous container" in content
    assert "The previous container is still running" in content
    assert "The previous container was stopped" in content
    assert 'curl --connect-timeout 2 --max-time 5 -ksS' in content


def test_manual_rollback_accepts_real_docker_container_id_format():
    content = (SCRIPTS / "nct-rollback-upgrade.sh").read_text(encoding="utf-8")
    function = "valid_container_id() {" + content.split("valid_container_id() {", 1)[1].split("\n}", 1)[0] + "\n}"
    valid = "a" * 64
    assert subprocess.run(
        ["sh", "-c", f"{function}\nvalid_container_id {valid}"], check=False
    ).returncode == 0
    assert subprocess.run(
        ["sh", "-c", f"{function}\nvalid_container_id sha256:{valid}"], check=False
    ).returncode != 0


def test_all_range_paths_ignore_checksum_file_line_endings():
    scripts = (*START_SCRIPTS, SCRIPTS / "nct-upgrade.sh", SCRIPTS / "nct-migrate-data.sh")
    for script in scripts:
        content = script.read_text(encoding="utf-8")
        assert "awk 'NR == 1 { print $1; exit }'" in content
        assert 'sha256sum "$ARCHIVE"' in content

    direct = (SCRIPTS / "nct-range-direct-deploy.sh").read_text(encoding="utf-8")
    assert "awk 'NR == 1 { print $1; exit }'" in direct
    assert 'sha256sum "$archive"' in direct


def test_start_scripts_accept_verified_upgrade_account_count():
    for name in ("nct-start-compose.sh", "nct-start-docker.sh", "nct-start-legacy.sh"):
        content = (SCRIPTS / name).read_text(encoding="utf-8")
        assert 'account_count="${NCT_UPGRADE_ACCOUNT_COUNT:-}"' in content
        assert 'if [ ! -f "$DATA_DIR/analyzer.db" ]' in content
        assert ':ro,z' in content
        assert '?mode=ro' in content
        assert 'case "$account_count" in' in content
        assert 'The NCT account count is invalid.' in content
