from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
START_SCRIPTS = (
    SCRIPTS / "nct-start-legacy.sh",
    SCRIPTS / "nct-start-docker.sh",
    SCRIPTS / "nct-start-compose.sh",
)


def test_range_start_scripts_share_the_operator_facing_defaults():
    for script in START_SCRIPTS:
        content = script.read_text(encoding="utf-8")
        assert "HOST_PORT=8445" in content
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
    for script in START_SCRIPTS:
        assert script.name in content
    assert "nct-set-admin.sh" in content
    assert "nct-migrate-data.sh" in content
    assert "/var/lib/nct/data" in content
    assert "nmap-terrain-analyzer" not in content
    assert "API **1.41 or newer**" in content
    assert "API **1.39 or 1.40**" in content
    assert "older than **1.39**" in content


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
    assert "NCT has active work" in content
    assert 'tar -C "$PERSIST_ROOT" -czf "$backup" data' in content
    assert 'sha256sum "$backup"' in content
    assert "nct-upgrade-rollback-$timestamp" in content
    assert "Stored record count decreased" in content
    assert 'NCT_UPGRADE_ACCOUNT_COUNT="$account_count" sh "$start_script" "$RANGE_IP"' in content
    assert 'docker exec "$CONTAINER" python -c "$snapshot_code"' in content
    assert 'snapshot "$before" container' in content
    assert 'snapshot "$after" container' in content
    assert '("-wal", "-shm", "-journal")' in content
    assert content.index("trap restore_original EXIT") < content.index(
        'original_stopped=yes\n    docker stop "$CONTAINER"'
    )
    assert 'api_at_least "$server_api" 1.41' in content
    assert 'api_at_least "$server_api" 1.39' in content
    assert 'docker volume rm' not in content
    assert 'rm -rf' not in content


def test_start_scripts_accept_verified_upgrade_account_count():
    for name in ("nct-start-compose.sh", "nct-start-docker.sh", "nct-start-legacy.sh"):
        content = (SCRIPTS / name).read_text(encoding="utf-8")
        assert 'account_count="${NCT_UPGRADE_ACCOUNT_COUNT:-}"' in content
        assert 'if [ ! -f "$DATA_DIR/analyzer.db" ]' in content
        assert ':ro,z' in content
        assert '?mode=ro' in content
        assert 'case "$account_count" in' in content
        assert 'The NCT account count is invalid.' in content
