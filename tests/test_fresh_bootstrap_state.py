import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "nct-fresh-bootstrap-state.py"
IMAGE_HELPER = ROOT / "scripts" / "nct-verify-loaded-images.py"


def runtime(container: str, image: str, image_id: str, root: Path) -> dict:
    return {
        "Id": "container-owned-by-fresh-install",
        "Name": "/" + container,
        "Image": image_id,
        "Path": "uvicorn",
        "Args": [
            "app.main:app", "--host", "0.0.0.0", "--port", "8445",
            "--loop", "asyncio", "--http", "h11",
            "--ssl-certfile", "/run/tls/nct-server.crt",
            "--ssl-keyfile", "/run/tls/nct-server.key",
        ],
        "State": {"Running": True},
        "Config": {
            "Image": image,
            "Env": [
                "NCT_AUTH_MODE=local", "NCT_SESSION_HOURS=12", "NCT_COOKIE_SECURE=1",
                "NCT_BOOTSTRAP_ADMIN=admin",
                "NCT_BOOTSTRAP_PASSWORD_FILE=/run/secrets/nct_bootstrap_password",
                "NCT_RETIREMENT_GUARD_MODE=required",
                "NCT_RETIREMENT_GUARD_DIR=/run/nct-retirement-guard",
                "NCT_RETIREMENT_DATA_IDENTITY=bind:" + str(root / "data"),
                "NCT_BUILD_ID=fixture",
            ],
        },
        "HostConfig": {
            "Privileged": False,
            "CapAdd": ["CAP_NET_RAW"],
            "CapDrop": None,
            "SecurityOpt": None,
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "NetworkMode": "bridge",
            "PortBindings": {"8445/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18445"}]},
        },
        "Mounts": [
            {"Type": "bind", "Destination": "/data", "Source": str(root / "data"), "RW": True},
            {"Type": "bind", "Destination": "/run/nct-retirement-guard", "Source": str(root / "retirement-guard"), "RW": True},
            {"Type": "bind", "Destination": "/run/tls/nct-server.crt", "Source": str(root / "server.crt"), "RW": False},
            {"Type": "bind", "Destination": "/run/tls/nct-server.key", "Source": str(root / "server.key"), "RW": False},
            {"Type": "bind", "Destination": "/run/secrets/nct_bootstrap_password", "Source": str(root / "secret"), "RW": False},
        ],
    }


def helper_args(root: Path, action: str) -> list[str]:
    return [
        sys.executable, str(HELPER), action,
        "--receipt", str(root / "deployment" / "bootstrap" / "fresh-resume.json"),
        "--container", "nct-fresh-fixture",
        "--image-reference", "network-characterization-tool:fixture",
        "--image-id", "sha256:fixture-image",
        "--admin-user", "admin",
        "--range-ip", "127.0.0.1",
        "--bind-address", "127.0.0.1",
        "--host-port", "18445",
        "--container-port", "8445",
        "--data-dir", str(root / "data"),
        "--retirement-guard-dir", str(root / "retirement-guard"),
        "--cert-file", str(root / "server.crt"),
        "--key-file", str(root / "server.key"),
        "--secret-file", str(root / "secret"),
        "--archive", str(root / "images.tar"),
    ]


@pytest.mark.skipif(os.name != "posix", reason="fake Docker executable is POSIX-only")
def test_fresh_resume_receipt_binds_exact_container_runtime_and_password_phase(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    inspect_path = tmp_path / "inspect.json"
    docker = tools / "docker"
    docker.write_text('#!/bin/sh\n[ "$1" = inspect ] || exit 91\ncat "$FAKE_INSPECT"\n')
    docker.chmod(0o700)
    (tmp_path / "data").mkdir()
    (tmp_path / "retirement-guard").mkdir()
    (tmp_path / "deployment" / "bootstrap").mkdir(parents=True, mode=0o700)
    for name, value in (
        ("server.crt", b"certificate"), ("server.key", b"key"),
        ("secret", b"temporary bootstrap secret"), ("images.tar", b"archive"),
    ):
        (tmp_path / name).write_bytes(value)
    value = runtime(
        "nct-fresh-fixture", "network-characterization-tool:fixture",
        "sha256:fixture-image", tmp_path,
    )
    inspect_path.write_text(json.dumps([value]))
    env = {
        **os.environ,
        "PATH": str(tools) + os.pathsep + os.environ["PATH"],
        "FAKE_INSPECT": str(inspect_path),
    }

    subprocess.run(helper_args(tmp_path, "create"), env=env, check=True)
    receipt_path = tmp_path / "deployment" / "bootstrap" / "fresh-resume.json"
    receipt = json.loads(receipt_path.read_text())
    assert receipt["phase"] == "awaiting_password"
    assert receipt["runtime"]["container_id"] == "container-owned-by-fresh-install"
    assert receipt["runtime"]["network_mode"] == "bridge"
    assert receipt["runtime"]["mounts"]["/run/secrets/nct_bootstrap_password"]["writable"] is False
    subprocess.run(helper_args(tmp_path, "verify"), env=env, check=True)

    guard_mount = next(
        item for item in value["Mounts"]
        if item["Destination"] == "/run/nct-retirement-guard"
    )
    for field, changed in (
        ("Type", "volume"), ("Source", str(tmp_path / "other")), ("RW", False),
    ):
        original = guard_mount[field]
        guard_mount[field] = changed
        inspect_path.write_text(json.dumps([value]))
        rejected = subprocess.run(
            helper_args(tmp_path, "verify"), env=env, capture_output=True, text=True
        )
        assert rejected.returncode != 0
        assert "mount contract changed" in rejected.stderr
        guard_mount[field] = original
    guard_mount["Source"] = str(tmp_path / "data")
    inspect_path.write_text(json.dumps([value]))
    overlapping_args = helper_args(tmp_path, "verify")
    overlapping_args[overlapping_args.index("--retirement-guard-dir") + 1] = str(tmp_path / "data")
    rejected = subprocess.run(
        overlapping_args, env=env, capture_output=True, text=True
    )
    assert rejected.returncode != 0
    assert "not separate from evidence data" in rejected.stderr
    guard_mount["Source"] = str(tmp_path / "retirement-guard")
    retirement_env = value["Config"]["Env"]
    value["Config"]["Env"] = [
        item for item in retirement_env
        if not item.startswith("NCT_RETIREMENT_GUARD_MODE=")
    ]
    inspect_path.write_text(json.dumps([value]))
    rejected = subprocess.run(
        helper_args(tmp_path, "verify"), env=env, capture_output=True, text=True
    )
    assert rejected.returncode != 0
    assert "environment contract changed" in rejected.stderr
    value["Config"]["Env"] = retirement_env
    inspect_path.write_text(json.dumps([value]))

    subprocess.run(
        [
            sys.executable, str(HELPER), "mark-password-committed",
            "--receipt", str(receipt_path),
            "--container-id", "container-owned-by-fresh-install",
            "--admin-user", "admin",
        ],
        check=True,
    )
    assert json.loads(receipt_path.read_text())["phase"] == "password_committed"
    subprocess.run(helper_args(tmp_path, "verify"), env=env, check=True)

    value["Config"]["Env"] = [
        item for item in value["Config"]["Env"] if not item.startswith("NCT_BOOTSTRAP_")
    ]
    value["Mounts"] = [
        item for item in value["Mounts"]
        if item["Destination"] != "/run/secrets/nct_bootstrap_password"
    ]
    inspect_path.write_text(json.dumps([value]))
    release, manifest = tmp_path / "release.json", tmp_path / "PACKAGE-MANIFEST.sha256"
    release.write_text('{"release":"exact"}')
    manifest.write_text("manifest")
    ready_args = [
        sys.executable, str(HELPER), "mark-runtime-ready",
        "--receipt", str(receipt_path), "--admin-user", "admin",
        "--release", str(release), "--manifest", str(manifest),
        "--archive", str(tmp_path / "images.tar"),
    ]
    subprocess.run(ready_args, env=env, check=True)
    assert json.loads(receipt_path.read_text())["phase"] == "runtime_ready"
    ready_args[2] = "verify-runtime-ready"
    subprocess.run(ready_args, env=env, check=True)

    value["Mounts"].reverse()
    inspect_path.write_text(json.dumps([value]))
    subprocess.run(ready_args, env=env, check=True)

    value["Mounts"].append(
        {"Destination": "/unexpected", "Source": str(tmp_path / "other"), "RW": True}
    )
    inspect_path.write_text(json.dumps([value]))
    rejected = subprocess.run(ready_args, env=env, capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "mount contract changed" in rejected.stderr
    assert json.loads(receipt_path.read_text())["phase"] == "runtime_ready"


@pytest.mark.skipif(os.name != "posix", reason="fake Docker executable is POSIX-only")
def test_loaded_image_verifier_accepts_modern_and_classic_package_identities(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    docker = tools / "docker"
    docker.write_text(
        '#!/bin/sh\ncase "$5" in modern) echo sha256:modern-export;; classic) echo sha256:classic-config;; *) echo sha256:foreign;; esac\n'
    )
    docker.chmod(0o700)
    release = tmp_path / "release.json"
    release.write_text(
        json.dumps(
            {
                "images": {
                    "modern": {
                        "export_runtime_id": "sha256:modern-export",
                        "archive_config_digest": "sha256:modern-config",
                    },
                    "classic": {
                        "export_runtime_id": "sha256:classic-export",
                        "archive_config_digest": "sha256:classic-config",
                    },
                }
            }
        )
    )
    env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
    subprocess.run([sys.executable, str(IMAGE_HELPER), str(release)], env=env, check=True)
    release.write_text(
        json.dumps(
            {"images": {"foreign": {"export_runtime_id": "sha256:expected", "archive_config_digest": "sha256:also-expected"}}}
        )
    )
    rejected = subprocess.run(
        [sys.executable, str(IMAGE_HELPER), str(release)], env=env, capture_output=True, text=True
    )
    assert rejected.returncode != 0
    assert "does not match the package" in rejected.stderr
