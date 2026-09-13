import os
import hashlib
from pathlib import Path
import subprocess


SCRIPT = (Path(__file__).parents[1] / "scripts" / "nct-deploy.sh").read_text()
RECOVERY = (Path(__file__).parents[1] / "scripts" / "nct-admin-recover.sh").read_text()


def run_launcher_preflight(
    tmp_path: Path,
    *args: str,
    compose_mode: str = "absent",
    api_version: str = "1.49",
    architecture: str = "amd64",
    os_type: str = "linux",
    occupied_port: bool = False,
    existing: str = "none",
    docker_subnet: str = "172.17.0.0/16",
    host_route: str = "10.0.0.0/24",
    overlap: bool = False,
    thread_probe: str = "pass",
) -> subprocess.CompletedProcess[str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        """#!/bin/sh
case "$1" in
  info)
    case "${3:-}" in
      *Architecture*) printf '%s\\n' "${FAKE_ARCHITECTURE:-amd64}" ;;
      *OSType*) printf '%s\\n' "${FAKE_OS_TYPE:-linux}" ;;
    esac
    ;;
  version)
    case "${3:-}" in
      *APIVersion*) printf '%s\\n' "${FAKE_DOCKER_API:-1.49}" ;;
      *) printf '28.0.1\\n' ;;
    esac
    ;;
  context) printf 'default\\n' ;;
  compose)
    if [ "${FAKE_COMPOSE_PLUGIN:-no}" = "yes" ]; then printf '2.27.1\\n'; else exit 1; fi
    ;;
  image)
    case "${4:-}" in
      *RepoDigests*) printf 'nct@example.invalid/fixture@sha256:fake\\n' ;;
      *Config.Env*) printf 'NCT_APP_VERSION=0.14.0-test\\nNCT_BUILD_ID=test-build\\n' ;;
      *)
        if [ "${3:-}" = "--format" ]; then printf 'sha256:fake\\n'; fi
        ;;
    esac
    ;;
  ps)
    if [ "${2:-}" = "-aq" ] && [ "${FAKE_EXISTING:-none}" != "none" ]; then
      printf 'fixture-container\\n'
    fi
    ;;
  inspect)
    case "${3:-}" in
      *Config.Image*) printf 'nct:older-build\\n' ;;
      *'.Image'*) printf 'sha256:older\\n' ;;
      *Mounts*) printf 'nct-data\\n' ;;
      *Config.Env*) printf 'disabled\\n' ;;
    esac
    ;;
  exec)
    [ "${FAKE_EXISTING:-none}" != "active" ] || exit 42
    ;;
  port)
    [ "${FAKE_EXISTING:-none}" = "none" ] || printf '127.0.0.1:8766\\n'
    ;;
  network)
    if [ "${2:-}" = "ls" ]; then printf 'fixture-network\\n'; else printf '%s\\n' "${FAKE_DOCKER_SUBNET:-172.17.0.0/16}"; fi
    ;;
  run)
    case "$*" in
      *threading.Thread*)
        if [ "${FAKE_THREAD_PROBE:-pass}" = "blocked" ]; then
          case "$*" in *seccomp=unconfined*) exit 0 ;; *) exit 1 ;; esac
        elif [ "${FAKE_THREAD_PROBE:-pass}" = "fail" ]; then
          exit 1
        fi
        ;;
      *NCT_DOCKER_NETWORKS*)
        if [ "${FAKE_OVERLAP:-no}" = "yes" ]; then
          printf '%s overlaps %s (host LAN/VPN route)\\n' "${FAKE_DOCKER_SUBNET}" "${FAKE_HOST_ROUTE}"
        else
          printf 'none\\n'
        fi
        ;;
      *saved_networks*) ;;
      *) printf '0\\n' ;;
    esac
    ;;
esac
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    fake_curl = fake_bin / "curl"
    fake_curl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_curl.chmod(0o755)
    fake_ss = fake_bin / "ss"
    fake_ss.write_text(
        "#!/bin/sh\n"
        "if [ \"${FAKE_OCCUPIED_PORT:-no}\" = \"yes\" ]; then \n"
        "  printf 'LISTEN 0 128 127.0.0.1:8766 0.0.0.0:*\\n'\n"
        "fi\n",
        encoding="utf-8",
    )
    fake_ss.chmod(0o755)
    fake_ip = fake_bin / "ip"
    fake_ip.write_text(
        "#!/bin/sh\nprintf '%s dev eth0 proto kernel scope link\\n' \"${FAKE_HOST_ROUTE:-10.0.0.0/24}\"\n",
        encoding="utf-8",
    )
    fake_ip.chmod(0o755)
    if compose_mode == "legacy":
        fake_legacy_compose = fake_bin / "docker-compose"
        fake_legacy_compose.write_text("#!/bin/sh\nprintf '1.29.2\\n'\n", encoding="utf-8")
        fake_legacy_compose.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["TMPDIR"] = str(tmp_path)
    environment["FAKE_DOCKER_API"] = api_version
    environment["FAKE_ARCHITECTURE"] = architecture
    environment["FAKE_OS_TYPE"] = os_type
    environment["FAKE_OCCUPIED_PORT"] = "yes" if occupied_port else "no"
    environment["FAKE_EXISTING"] = existing
    environment["FAKE_DOCKER_SUBNET"] = docker_subnet
    environment["FAKE_HOST_ROUTE"] = host_route
    environment["FAKE_OVERLAP"] = "yes" if overlap else "no"
    environment["FAKE_THREAD_PROBE"] = thread_probe
    if compose_mode == "plugin":
        environment["FAKE_COMPOSE_PLUGIN"] = "yes"
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


def test_launcher_classifies_the_range_compatibility_ladder():
    for required in (
        'compatibility_tier="compose-v2"',
        'compatibility_tier="legacy-compose-v1"',
        'compatibility_tier="direct-engine"',
        'compatibility_tier="legacy-range-direct-engine"',
        'compatibility_status="supported"',
        'compatibility_status="degraded"',
        'compatibility_status="workaround"',
        'Range compatibility: unsupported Docker API',
        'offline NCT appliance fallback',
        'Range compatibility: $compatibility_status · $compatibility_tier',
    ):
        assert required in SCRIPT


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


def test_launcher_requires_exact_prior_profile_promotion_receipts():
    for required in (
        '--promote-from-receipt FILE',
        'deployment requires --promote-from-receipt from the preceding acceptance profile',
        'required_receipt_profile="test"',
        'required_receipt_profile="range"',
        'Promotion receipt image ID does not match',
        'Promotion receipt build does not match',
        'Promotion receipt version does not match',
        'application, runtime-tool, and NET_RAW acceptance results',
    ):
        assert required in SCRIPT


def test_launcher_writes_atomic_promotion_receipts_after_full_acceptance():
    for required in (
        'write_promotion_receipt()',
        'promotion_ready=yes',
        'application_health=pass',
        'external_access=pass',
        'known_limitations=',
        'rollback_container=',
        'receipt_tmp=',
        'mv "$receipt_tmp" "$receipt_file"',
        'write_promotion_receipt || rollback',
    ):
        assert required in SCRIPT
    assert SCRIPT.index('write_promotion_receipt || rollback\n') > SCRIPT.index(
        'curl --fail --silent --show-error "$access_url/health"'
    )


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


def test_range_preflight_accepts_only_an_exact_test_receipt(tmp_path):
    receipt = tmp_path / "test.receipt"
    receipt.write_text(
        "\n".join(
            (
                "schema=1",
                "profile=test",
                "promotion_ready=yes",
                "image_id=sha256:fake",
                "version=0.14.0-test",
                "build=test-build",
                "application_health=pass",
                "runtime_tools=ready",
                "net_raw=ready",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    accepted = run_launcher_preflight(
        tmp_path / "accepted-range",
        "--profile",
        "range",
        "--image",
        "nct:0.14.0-test",
        "--promote-from-receipt",
        str(receipt),
    )
    assert accepted.returncode == 0, accepted.stderr
    assert "Preflight complete" in accepted.stdout
    assert "Range compatibility: degraded · direct-engine" in accepted.stdout

    receipt.write_text(receipt.read_text().replace("sha256:fake", "sha256:other"))
    rejected = run_launcher_preflight(
        tmp_path / "rejected-range",
        "--profile",
        "range",
        "--image",
        "nct:0.14.0-test",
        "--promote-from-receipt",
        str(receipt),
    )
    assert rejected.returncode == 1
    assert "Promotion receipt image ID does not match" in rejected.stderr


def test_preflight_reports_compose_v2_legacy_and_direct_engine_tiers(tmp_path):
    expected = {
        "plugin": "supported · compose-v2",
        "legacy": "degraded · legacy-compose-v1",
        "absent": "degraded · direct-engine",
    }
    for mode, outcome in expected.items():
        completed = run_launcher_preflight(
            tmp_path / mode,
            "--profile",
            "test",
            "--image",
            "nct:0.14.0-test",
            compose_mode=mode,
        )
        assert completed.returncode == 0, completed.stderr
        assert f"Range compatibility: {outcome}" in completed.stdout


def test_preflight_rejects_old_api_unsupported_architecture_and_windows_daemon(tmp_path):
    old_api = run_launcher_preflight(
        tmp_path / "old-api",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        api_version="1.40",
    )
    assert old_api.returncode == 1
    assert "Docker API 1.40 needs the verified recurring-VM workaround" in old_api.stderr

    unsupported_arch = run_launcher_preflight(
        tmp_path / "architecture",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        architecture="s390x",
    )
    assert unsupported_arch.returncode == 1
    assert "Unsupported Docker architecture: s390x" in unsupported_arch.stderr

    windows = run_launcher_preflight(
        tmp_path / "windows",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        os_type="windows",
    )
    assert windows.returncode == 1
    assert "requires Docker Linux containers" in windows.stderr


def test_range_can_opt_into_the_verified_legacy_vm_runtime(tmp_path):
    assert '--security-opt seccomp=unconfined' in SCRIPT
    assert 'uvicorn app.main:app --host 0.0.0.0 --port 8080 --loop asyncio --http h11' in SCRIPT
    assert SCRIPT.index('Promotion receipt does not contain complete') < SCRIPT.index(
        'docker run --rm --entrypoint python'
    )
    assert 'Mission promotion requires a supported Range runtime receipt' in SCRIPT
    receipt = tmp_path / "test.receipt"
    receipt.write_text(
        "profile=test\npromotion_ready=yes\nimage_id=sha256:fake\n"
        "version=0.14.0-test\nbuild=test-build\napplication_health=pass\n"
        "runtime_tools=ready\nnet_raw=ready\ncompatibility_status=supported\n",
        encoding="utf-8",
    )
    completed = run_launcher_preflight(
        tmp_path / "legacy-range",
        "--profile",
        "range",
        "--image",
        "nct:0.14.0-test",
        "--promote-from-receipt",
        str(receipt),
        "--allow-legacy-range-runtime",
        api_version="1.39",
        thread_probe="blocked",
    )
    assert completed.returncode == 0, completed.stderr
    assert "Range compatibility: workaround · legacy-range-direct-engine" in completed.stdout
    assert "Legacy runtime probe: seccomp-workaround-pass" in completed.stdout
    log_text = next((tmp_path / "legacy-range" / "state" / "logs").glob("deploy-*.log")).read_text()
    assert "runtime_seccomp=unconfined" in log_text
    assert "runtime_uvicorn=asyncio-h11" in log_text


def test_legacy_range_runtime_fails_closed_when_thread_probe_still_fails(tmp_path):
    receipt = tmp_path / "test.receipt"
    receipt.write_text(
        "profile=test\npromotion_ready=yes\nimage_id=sha256:fake\n"
        "version=0.14.0-test\nbuild=test-build\napplication_health=pass\n"
        "runtime_tools=ready\nnet_raw=ready\ncompatibility_status=supported\n",
        encoding="utf-8",
    )
    completed = run_launcher_preflight(
        tmp_path / "legacy-fail",
        "--profile",
        "range",
        "--image",
        "nct:0.14.0-test",
        "--promote-from-receipt",
        str(receipt),
        "--allow-legacy-range-runtime",
        api_version="1.39",
        thread_probe="fail",
    )
    assert completed.returncode == 1
    assert "runtime probe failed even with" in completed.stderr


def test_legacy_range_runtime_is_not_available_to_test_or_mission(tmp_path):
    for profile in ("test", "mission"):
        completed = run_launcher_preflight(
            tmp_path / profile,
            "--profile",
            profile,
            "--image",
            "nct:0.14.0-test",
            "--allow-legacy-range-runtime",
        )
        assert completed.returncode == 1
        assert "restricted to the Range profile" in completed.stderr


def test_preflight_verifies_offline_archive_checksum(tmp_path):
    archive = tmp_path / "nct.tar"
    archive.write_bytes(b"offline NCT image fixture")
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    accepted = run_launcher_preflight(
        tmp_path / "offline-pass",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        "--image-archive",
        str(archive),
        "--image-sha256",
        checksum,
        "--offline",
    )
    assert accepted.returncode == 0, accepted.stderr

    rejected = run_launcher_preflight(
        tmp_path / "offline-fail",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        "--image-archive",
        str(archive),
        "--image-sha256",
        "0" * 64,
        "--offline",
    )
    assert rejected.returncode == 1
    assert "checksum does not match" in rejected.stderr


def test_preflight_selects_an_alternate_test_port_without_touching_listener(tmp_path):
    completed = run_launcher_preflight(
        tmp_path / "occupied-port",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        occupied_port=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "selected 8767" in completed.stderr
    assert "Access: local on 127.0.0.1:8767" in completed.stdout


def test_preflight_preserves_idle_existing_nct_and_blocks_active_work(tmp_path):
    idle = run_launcher_preflight(
        tmp_path / "idle-existing",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        existing="idle",
    )
    assert idle.returncode == 0, idle.stderr
    assert "Existing: nct:older-build · Data: nct-data" in idle.stdout

    active = run_launcher_preflight(
        tmp_path / "active-existing",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        existing="active",
    )
    assert active.returncode == 1
    assert "has an active scan, collection, update, or migration" in active.stderr


def test_preflight_warns_for_test_overlap_and_blocks_range_overlap(tmp_path):
    test_result = run_launcher_preflight(
        tmp_path / "test-overlap",
        "--profile",
        "test",
        "--image",
        "nct:0.14.0-test",
        docker_subnet="10.0.0.0/16",
        host_route="10.0.0.0/24",
        overlap=True,
    )
    assert test_result.returncode == 0, test_result.stderr
    assert "Docker network overlap detected" in test_result.stderr
    assert "Docker network overlap: conflict" in test_result.stdout

    receipt = tmp_path / "range-source.receipt"
    receipt.write_text(
        "profile=test\npromotion_ready=yes\nimage_id=sha256:fake\n"
        "version=0.14.0-test\nbuild=test-build\napplication_health=pass\n"
        "runtime_tools=ready\nnet_raw=ready\n",
        encoding="utf-8",
    )
    range_result = run_launcher_preflight(
        tmp_path / "range-overlap",
        "--profile",
        "range",
        "--image",
        "nct:0.14.0-test",
        "--promote-from-receipt",
        str(receipt),
        docker_subnet="10.0.0.0/16",
        host_route="10.0.0.0/24",
        overlap=True,
    )
    assert range_result.returncode == 1
    assert "Choose a non-overlapping Docker address pool" in range_result.stderr


def test_launcher_inventory_contract_includes_routes_saved_networks_and_docker_cidrs():
    for required in (
        'ip -4 route show',
        'docker network ls -q',
        'docker network inspect',
        'SELECT cidr FROM saved_networks WHERE active = 1',
        'ipaddress.ip_network',
        'network_overlap_detail',
        'Choose a non-overlapping Docker address pool',
    ):
        assert required in SCRIPT


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
    assert SCRIPT.index('write_promotion_receipt || rollback\n') < banner


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
