from pathlib import Path


SCRIPT = (Path(__file__).parents[1] / "scripts" / "nct-deploy.sh").read_text()


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
