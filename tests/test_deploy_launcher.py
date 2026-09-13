import os
from pathlib import Path
import subprocess


SCRIPT = (Path(__file__).parents[1] / "scripts" / "nct-deploy.sh").read_text()
RECOVERY = (Path(__file__).parents[1] / "scripts" / "nct-admin-recover.sh").read_text()


def run_launcher_preflight(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        """#!/bin/sh
case "$1" in
  info)
    case "${3:-}" in
      *Architecture*) printf 'amd64\\n' ;;
      *OSType*) printf 'linux\\n' ;;
    esac
    ;;
  version)
    case "${3:-}" in
      *APIVersion*) printf '1.49\\n' ;;
      *) printf '28.0.1\\n' ;;
    esac
    ;;
  context) printf 'default\\n' ;;
  compose) exit 1 ;;
  image) exit 0 ;;
esac
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    fake_curl = fake_bin / "curl"
    fake_curl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_curl.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["TMPDIR"] = str(tmp_path)
    return subprocess.run(
        [
            "sh",
            str(Path(__file__).parents[1] / "scripts" / "nct-deploy.sh"),
            "--check-only",
            "--state-dir",
            str(tmp_path / "state"),
            *args,
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )


def test_launcher_has_profiles_and_safe_access_modes():
    assert '--profile test|range|mission' in SCRIPT
    assert '--access local|lan' in SCRIPT
    assert 'Local access may bind only to a loopback address' in SCRIPT
    assert 'Choose one LAN address instead of exposing NCT on every interface' in SCRIPT


def test_launcher_checks_runtime_versions_conflicts_and_active_work():
    for required in (
        'docker info', 'Server.APIVersion', 'docker compose version',
        'docker-compose version', 'Architecture', 'port $published_port',
        'awaiting_fallback_approval', 'Another deployment launcher appears active',
    ):
        assert required in SCRIPT
    assert 'active_rc=$?' in SCRIPT
    assert '[ "$active_rc" -ne 42 ]' in SCRIPT


def test_launcher_supports_offline_integrity_backup_health_and_rollback():
    for required in (
        'sha256sum', 'docker load -i', 'tar -czf', '/health',
        'rollback()', 'docker rename', 'restart unless-stopped', 'cap-add NET_RAW',
    ):
        assert required in SCRIPT


def test_launcher_records_immutable_image_identity_and_exact_build():
    for required in (
        'target_image_id=$(docker image inspect', 'target_repo_digests=',
        'target_build=', 'target_version=', 'All deployable NCT images must declare NCT_BUILD_ID',
        'All deployable NCT images must declare NCT_APP_VERSION',
        'reported_build" = "$target_build',
    ):
        assert required in SCRIPT
    assert 'Test, Range, and Mission deployments require a versioned image reference, not :latest' in SCRIPT
    assert 'image=""' in SCRIPT
    assert 'mutable defaults are not permitted' in SCRIPT


def test_launcher_requires_checksums_for_every_offline_archive():
    assert 'Every offline image archive requires --image-sha256 before Test, Range, or Mission use.' in SCRIPT
    assert 'The supplied offline image archive has no checksum.' not in SCRIPT


def test_launcher_rejects_missing_or_mutable_image_references(tmp_path):
    missing = run_launcher_preflight(tmp_path / "missing", "--profile", "test")
    assert missing.returncode == 1
    assert "Choose an explicit versioned NCT image" in missing.stderr

    for index, image in enumerate(("network-characterization-tool:latest", "network-characterization-tool")):
        rejected = run_launcher_preflight(
            tmp_path / f"mutable-{index}", "--profile", "test", "--image", image
        )
        assert rejected.returncode == 1
        assert "Test, Range, and Mission deployments require" in rejected.stderr


def test_launcher_rejects_unverified_offline_archives_in_test(tmp_path):
    archive = tmp_path / "nct.tar"
    archive.write_bytes(b"retained test artifact")
    rejected = run_launcher_preflight(
        tmp_path / "unchecked-archive",
        "--profile",
        "test",
        "--image",
        "network-characterization-tool:0.14.0-test",
        "--image-archive",
        str(archive),
    )
    assert rejected.returncode == 1
    assert "Every offline image archive requires --image-sha256" in rejected.stderr


def test_launcher_is_idempotent_for_an_already_current_direct_deployment():
    assert 'existing_image_id=$(docker inspect' in SCRIPT
    assert 'existing_image_id" = "$target_image_id' in SCRIPT
    assert 'result=already-current' in SCRIPT
    assert 'no backup or container swap was needed' in SCRIPT
    assert 'state_file="$state_dir/current.env"' in SCRIPT
    assert 'mv "$state_tmp" "$state_file"' in SCRIPT


def test_launcher_detects_docker_and_host_port_listeners():
    assert 'port_conflict_owner()' in SCRIPT
    assert 'command -v ss' in SCRIPT
    assert 'command -v netstat' in SCRIPT
    assert 'host listener at ' in SCRIPT
    assert 'selected_app_port=%s' in SCRIPT
    assert 'existing_app_port=${existing_app_binding##*:}' in SCRIPT


def test_launcher_validates_scanning_tools_and_raw_packet_capability():
    for required in (
        'command -v nmap', 'command -v fping', 'command -v tcpdump',
        'command -v ssh', 'tcpdump -D', 'socket.SOCK_RAW',
        'grep -F NET_RAW', 'runtime_tools=%s',
    ):
        assert required in SCRIPT


def test_launcher_requires_mission_tls_and_narrow_firewall_authority():
    assert 'Mission deployment is intentionally fail-closed' in SCRIPT
    assert 'Mission profile requires a validated TLS certificate and key' in SCRIPT
    assert '--configure-firewall' in SCRIPT
    assert 'source address=$source_cidr' in SCRIPT
    assert 'No firewall change was made' in SCRIPT
    assert SCRIPT.index('Proceed with the NCT container swap?') < SCRIPT.index('apply_firewall_rule || rollback')


def test_launcher_binds_direct_lan_access_to_selected_address():
    assert '-p "$bind_address:$app_port:8080"' in SCRIPT
    assert '-p "127.0.0.1:$app_port:8080"' not in SCRIPT
    assert 'never binds to every interface' not in SCRIPT  # documentation wording is not the safety control
    assert 'Choose one LAN address instead of exposing NCT on every interface' in SCRIPT


def test_launcher_rolls_back_application_proxy_and_firewall():
    assert 'rollback_proxy_name' in SCRIPT
    assert 'docker rename "$rollback_proxy_name" "$proxy_name"' in SCRIPT
    assert 'remove_firewall_rule' in SCRIPT
    assert 'trap handle_interruption HUP INT TERM' in SCRIPT


def test_launcher_prints_verified_nct_banner_only_at_success_end():
    banner = SCRIPT.index('Network Characterization Tool')
    health = SCRIPT.index('reported_build=$(docker exec')
    assert banner > health
    assert 'Available at $access_url' in SCRIPT


def test_launcher_bootstraps_first_admin_without_fixed_credentials():
    for required in (
        '--auth disabled|local', '--admin-user USER', '--admin-password-file FILE',
        '--generate-admin-password', 'SELECT COUNT(*) FROM analyst_users',
        'NCT_BOOTSTRAP_PASSWORD_FILE=/run/secrets/nct_bootstrap_password',
        'Bootstrap Administrator verified',
    ):
        assert required in SCRIPT
    assert 'Range deployment requires local authentication' in SCRIPT
    assert 'NCT_BOOTSTRAP_PASSWORD=' not in SCRIPT
    assert 'admin:admin' not in SCRIPT.lower()


def test_launcher_detaches_one_time_bootstrap_secret_and_preserves_accounts():
    verification = SCRIPT.index('from app.auth import verify_credentials')
    detach = SCRIPT.index('docker rm -f "$container"', verification)
    permanent_start = SCRIPT.index('start_nct_container "no"', detach)
    assert verification < detach < permanent_start
    assert 'Preserving $account_count existing analyst account(s)' in SCRIPT
    assert 'auth_mode=%s' in SCRIPT
    assert 'chmod 600 "$bootstrap_password_file"' in SCRIPT


def test_host_recovery_is_admin_only_backed_up_and_secret_file_based():
    for required in (
        '--admin-user USER', '--password-file FILE', '--generate-password',
        'v "$data_volume:/data:ro"', 'tar -czf',
        'Recovery is restricted to Administrator accounts',
        'reset_user_password', 'set_user_disabled',
        '/run/secrets/nct_recovery_password:ro',
        'NCT has active work', 'chmod 600 "$password_file"',
        'action=password_reset_and_session_revocation',
    ):
        assert required in RECOVERY
    assert 'NCT_BOOTSTRAP_PASSWORD=' not in RECOVERY
    assert 'password=%s' not in RECOVERY
