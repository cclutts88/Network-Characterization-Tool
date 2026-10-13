import hashlib
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess

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

    assert "if [ -e /root/NCT-Air-Gapped-Range-Deployment ]; then" in content
    assert 'mkdir -m 0700 "$staging_dir"' in content
    assert 'unzip "$package_zip" -d "$staging_dir"' in content
    assert 'export NCT_WORKDIR="$staging_dir/NCT-Air-Gapped-Range-Deployment"' in content
    assert "leave it unchanged" in content
    assert 'sh "$NCT_WORKDIR/scripts/nct-upgrade.sh" RANGE_IP legacy' in content


def test_quick_start_verifies_the_outer_package_before_extraction():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )

    verify = 'checksum_file="$package_zip.sha256"'
    extract = 'unzip "$package_zip"'
    assert verify in content
    assert content.index(verify) < content.index(extract)
    assert '(cd /root && sha256sum -c "$(basename "$checksum_file")") || exit 1' in content
    assert 'echo "Package SHA-256: $actual_package_sha256"' in content
    assert "A missing" in content
    assert "does not stop installation" in content


def test_quick_start_requires_release_specific_scope_handoff_acceptance():
    content = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(content.split())

    assert "phase2-r9" in content
    assert "phase2-r5" in content
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
    assert 'PRAGMA foreign_key_check' in content
    assert 'SCHEMA_PREFLIGHT="$WORKDIR/scripts/nct-schema-preflight.py"' in content
    assert '"$original_image_id" python -c' in content
    assert 'PRAGMA wal_checkpoint(TRUNCATE)' in content
    assert '"$DATA_DIR:/data:ro,Z"' in content
    assert '"$IMAGE" python /opt/nct-schema-preflight.py --db /data/analyzer.db' in content
    assert 'schema_preflight=%s' in content
    assert 'NCT_HTTPS_PORT="$original_host_port" NCT_UPGRADE_ACCOUNT_COUNT="$account_count" sh "$start_script" "$RANGE_IP"' in content
    assert 'docker exec "$CONTAINER" python -c "$snapshot_code"' in content
    assert 'snapshot "$before"' in content
    assert content.index('docker stop "$CONTAINER"') < content.index('snapshot "$before"')
    assert content.index('PRAGMA wal_checkpoint(TRUNCATE)') < content.index(
        'python /opt/nct-schema-preflight.py'
    )
    assert 'snapshot "$after" container' in content
    assert '"analyzer.db-wal"' in content
    assert '"analyzer.db-shm"' in content
    assert '"analyzer.db-journal"' in content
    assert content.index("trap restore_original EXIT") < content.index(
        'original_stopped=yes\n    docker stop "$CONTAINER"'
    )
    assert 'api_at_least "$server_api" 1.41' in content
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
