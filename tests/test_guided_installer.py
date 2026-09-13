import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[1]
INSTALLER = ROOT / "scripts" / "install-nct.sh"
TLS_SETUP = ROOT / "scripts" / "setup-lab-https.sh"
INSTALLER_TEXT = INSTALLER.read_text()
TLS_TEXT = TLS_SETUP.read_text()


def run_plan(tmp_path: Path, preset: str, *, api: str = "1.49", answers: int = 12):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  info) exit 0 ;;\n"
        "  version) printf '%s\\n' \"${FAKE_DOCKER_API:-1.49}\" ;;\n"
        "  image) exit 0 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    preset_file = tmp_path / "preset.env"
    preset_file.write_text(preset, encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["FAKE_DOCKER_API"] = api
    return subprocess.run(
        ["sh", str(INSTALLER), "--preset", str(preset_file), "--plan-only"],
        input="\n" * answers,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )


def test_guided_test_plan_uses_saved_non_sensitive_defaults(tmp_path):
    completed = run_plan(
        tmp_path,
        "profile=test\naccess=local\ntls_enabled=no\napp_port=8766\n"
        "image=nct:0.14.0-test\noffline=no\nauth_mode=disabled\n",
    )
    assert completed.returncode == 0, completed.stderr
    assert "Guided Test / Range installer" in completed.stdout
    assert "Profile:          test" in completed.stdout
    assert "Access:           local on 127.0.0.1:8766" in completed.stdout
    assert "Plan complete" in completed.stdout
    assert "No certificate, firewall, image, container, or preset state was changed" in completed.stdout


def test_guided_range_plan_covers_legacy_tls_firewall_and_admin_prompts(tmp_path):
    completed = run_plan(
        tmp_path,
        "profile=range\naccess=lan\nbind_address=10.20.30.40\n"
        "tls_enabled=yes\ntls_mode=existing\ntls_cert=/transfer/server.crt\n"
        "tls_key=/transfer/server.key\ntls_ca=/transfer/root.crt\nhttps_port=8444\n"
        "configure_firewall=yes\nsource_cidr=10.20.30.0/24\n"
        "allow_legacy_range_runtime=yes\nimage=nct:0.14.0-range\n"
        "offline=yes\nuse_image_archive=no\npromotion_receipt=/transfer/test.receipt\n"
        "auth_mode=local\nadmin_user=nctadmin\n",
        api="1.39",
        answers=24,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Docker API 1.39 matches the older Range-host pattern" in completed.stdout
    assert "Access:           lan on 10.20.30.40:8444" in completed.stdout
    assert "Firewall:         yes from 10.20.30.0/24" in completed.stdout
    assert "Legacy workaround: yes" in completed.stdout
    assert "Authentication:   local" in completed.stdout


def test_installer_preflights_before_deploying_and_saves_only_after_success():
    preflight = INSTALLER_TEXT.index('sh "$@" --check-only')
    deploy = INSTALLER_TEXT.index('sh "$@" --yes')
    preset = INSTALLER_TEXT.index('preset_tmp="${preset_file}.tmp.$$"')
    assert preflight < deploy < preset
    for expected in (
        "Deployment profile (range/test)",
        "Server address analysts will use",
        "Approved analyst source subnet (CIDR)",
        "TLS material (generate/existing)",
        "Matching Test acceptance receipt",
        "Verify and stage the offline archive now",
        "Initial Administrator username",
        "--allow-legacy-range-runtime",
        "--configure-firewall",
        "--generate-admin-password",
    ):
        assert expected in INSTALLER_TEXT
    assert "password=" not in INSTALLER_TEXT.lower()
    assert INSTALLER_TEXT.index('docker load -i "$image_archive"') < INSTALLER_TEXT.index(
        'sh "$@" --check-only'
    )


def test_tls_helper_generates_only_certificates_and_refuses_overwrite(tmp_path):
    assert "docker compose" not in TLS_TEXT
    assert "docker run" not in TLS_TEXT
    first = subprocess.run(
        ["sh", str(TLS_SETUP), "192.0.2.10", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    cert = tmp_path / "tls" / "nct-server.crt"
    key = tmp_path / "tls" / "nct-server.key"
    ca = tmp_path / "certs" / "nct-lab-root.crt"
    assert cert.is_file() and key.is_file() and ca.is_file()
    san = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "IP Address:192.0.2.10" in san.stdout

    second = subprocess.run(
        ["sh", str(TLS_SETUP), "192.0.2.10", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert second.returncode == 1
    assert "Refusing to overwrite" in second.stderr
