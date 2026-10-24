from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "nct-fresh-install.py"
SCRIPT_PATH = ROOT / "scripts" / "nct-fresh-install.sh"
SPEC = importlib.util.spec_from_file_location("nct_fresh_install", HELPER_PATH)
assert SPEC and SPEC.loader
fresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fresh)


def runtime_inspect(data_type: str, data_source: str) -> list[dict]:
    data_mount = {
        "Type": data_type,
        "Name": data_source if data_type == "volume" else "",
        "Source": data_source if data_type == "bind" else "/var/lib/docker/volumes/example/_data",
        "Destination": "/data",
        "RW": True,
    }
    return [{
        "Config": {
            "Hostname": "nct-range",
            "Image": "nct:test-r24",
            "Entrypoint": None,
            "Cmd": ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8445",
                    "--ssl-certfile", "/run/tls/nct-server.crt", "--ssl-keyfile", "/run/tls/nct-server.key"],
            "Env": [
                "PATH=/usr/local/bin",
                "NCT_APP_VERSION=0.16.0",
                "NCT_BUILD_ID=r24-test",
                "NCT_AUTH_MODE=local",
                "NCT_SESSION_HOURS=12",
                "NCT_COOKIE_SECURE=1",
                "NCT_ARKIME_API_ENABLED=1",
                "NCT_ARKIME_API_PASSWORD_FILE=/run/secrets/old",
                "NCT_BOOTSTRAP_PASSWORD=must-not-copy",
            ],
        },
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": False,
            "CapAdd": ["NET_RAW"],
            "SecurityOpt": ["no-new-privileges"],
            "NetworkMode": "bridge",
            "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 4},
            "PortBindings": {"8445/tcp": [{"HostIp": "10.0.0.5", "HostPort": "8445"}]},
        },
        "Mounts": [
            data_mount,
            {"Type": "bind", "Source": "/var/lib/nct/tls/cert", "Destination": "/run/tls/nct-server.crt", "RW": False},
            {"Type": "bind", "Source": "/var/lib/nct/tls/key", "Destination": "/run/tls/nct-server.key", "RW": False},
            {"Type": "bind", "Source": "/var/lib/nct/bootstrap", "Destination": "/run/nct-bootstrap", "RW": False},
        ],
    }]


def test_inventory_covers_content_metadata_symlinks_and_hardlinks(tmp_path):
    root = tmp_path / "data"
    root.mkdir(mode=0o750)
    source = root / "evidence.bin"
    source.write_bytes(b"exact retained bytes")
    source.chmod(0o640)
    os.link(source, root / "evidence-hardlink.bin")
    os.symlink("evidence.bin", root / "evidence-link")

    result = fresh.inventory(root)

    assert result["contract"] == "nct-fresh-install-inventory:1"
    assert result["file_count"] == 2
    assert result["symlink_count"] == 1
    assert ["evidence-hardlink.bin", "evidence.bin"] in result["hardlink_sets"]
    rows = {row["path"]: row for row in result["entries"]}
    assert rows["evidence.bin"]["mode"] == 0o640
    assert rows["evidence.bin"]["sha256"] == rows["evidence-hardlink.bin"]["sha256"]
    assert rows["evidence-link"]["target"] == "evidence.bin"


@pytest.mark.parametrize("mount_type,old_source,new_source", [
    ("bind", "/var/lib/nct/data", "/var/lib/nct/nct-fresh-1"),
    ("volume", "nct-data", "nct-data-fresh-1"),
])
def test_plan_supports_bind_and_named_volume_without_inheriting_connectors(
    tmp_path, mount_type, old_source, new_source
):
    inspect_path = tmp_path / "inspect.json"
    inspect_path.write_text(json.dumps(runtime_inspect(mount_type, old_source)))
    data = tmp_path / "data"
    data.mkdir()
    (data / "evidence.bin").write_bytes(b"evidence")
    inventory = fresh.inventory(data)
    summary = fresh.data_summary(data)
    inventory_path = tmp_path / "inventory.json"
    summary_path = tmp_path / "summary.json"
    inventory_path.write_text(json.dumps(inventory))
    summary_path.write_text(json.dumps(summary))
    args = type("Args", (), {
        "inspect": inspect_path,
        "summary": summary_path,
        "inventory": inventory_path,
        "container": "nct",
        "container_id": "c" * 64,
        "prior_state": "running",
        "image_ref": "nct:test-r24",
        "image_id": "sha256:" + "a" * 64,
        "mount_type": mount_type,
        "data_source": old_source,
        "new_data_source": new_source,
        "retained_container": "nct-pre-fresh-1",
        "backup": Path("/backups/nct.tar.gz"),
        "backup_sha256": "b" * 64,
        "created_at": "2026-10-23T12:00:00Z",
    })()

    plan = fresh.create_plan(args)

    assert plan["old_data"] == {"type": mount_type, "source": old_source}
    assert plan["new_data"] == {"type": mount_type, "source": new_source}
    assert plan["runtime"]["restart_policy"] == {"name": "on-failure", "maximum_retry_count": 4}
    assert plan["runtime"]["health_url"] == "https://10.0.0.5:8445/health"
    assert plan["runtime"]["tls_treatment"].startswith("reuse exact")
    assert plan["runtime"]["omitted_environment_names"] == [
        "NCT_ARKIME_API_ENABLED", "NCT_ARKIME_API_PASSWORD_FILE"
    ]
    assert "must-not-copy" not in json.dumps(plan)
    assert plan["confirmation"] == f"FRESH-{plan['plan_digest'][:12]}"


def test_plan_refuses_shared_or_unexpected_runtime_surface(tmp_path):
    value = runtime_inspect("bind", "/var/lib/nct/data")
    value[0]["HostConfig"]["Privileged"] = True
    inspect_path = tmp_path / "inspect.json"
    inspect_path.write_text(json.dumps(value))
    with pytest.raises(fresh.FreshInstallError, match="privileged"):
        fresh._validate_runtime(inspect_path, "/var/lib/nct/data", "bind")

    value = runtime_inspect("bind", "/var/lib/nct/data")
    value[0]["Mounts"].append({
        "Type": "bind", "Source": "/host/unknown", "Destination": "/unknown", "RW": False
    })
    inspect_path.write_text(json.dumps(value))
    with pytest.raises(fresh.FreshInstallError, match="unsupported non-data mount"):
        fresh._validate_runtime(inspect_path, "/var/lib/nct/data", "bind")

    value = runtime_inspect("bind", "/var/lib/nct/data")
    value[0]["Config"]["Env"] = [
        entry.replace("NCT_AUTH_MODE=local", "NCT_AUTH_MODE=disabled")
        for entry in value[0]["Config"]["Env"]
    ]
    inspect_path.write_text(json.dumps(value))
    with pytest.raises(fresh.FreshInstallError, match="NCT_AUTH_MODE=local"):
        fresh._validate_runtime(inspect_path, "/var/lib/nct/data", "bind")

    value = runtime_inspect("bind", "/var/lib/nct/data")
    value[0]["Config"]["User"] = "1000:1000"
    inspect_path.write_text(json.dumps(value))
    with pytest.raises(fresh.FreshInstallError, match="custom container users"):
        fresh._validate_runtime(inspect_path, "/var/lib/nct/data", "bind")


def test_apply_isolation_rejects_late_old_or_new_mount_overlap():
    shared_old = [{
        "Id": "other",
        "Name": "/writer",
        "Mounts": [{"Type": "volume", "Name": "nct-old", "Source": "/volumes/nct-old"}],
    }]
    with pytest.raises(fresh.FreshInstallError, match="shares or overlaps"):
        fresh.check_isolation(shared_old, "target", "volume", "nct-old", "/volumes/nct-old")

    shared_new_parent = [{
        "Id": "other",
        "Name": "/future-writer",
        "Mounts": [{"Type": "bind", "Source": "/srv/nct", "Name": ""}],
    }]
    with pytest.raises(fresh.FreshInstallError, match="fresh data path"):
        fresh.check_isolation(
            shared_new_parent, "target", "bind", "/old/nct", "/old/nct", "/srv/nct/fresh"
        )

    root_mounted_sidecar = [{
        "Id": "other",
        "Name": "/root-reader",
        "Mounts": [{"Type": "bind", "Source": "/", "Name": ""}],
    }]
    with pytest.raises(fresh.FreshInstallError, match="shares or overlaps"):
        fresh.check_isolation(
            root_mounted_sidecar, "target", "bind", "/var/lib/nct/data", "/var/lib/nct/data"
        )


def test_failed_docker_inventory_cannot_be_reported_as_verified_stopped():
    content = SCRIPT_PATH.read_text(encoding="utf-8")
    functions = content[content.index("docker_probe() {"):content.index("remove_helper() {")]
    exercise = functions + r'''
CONTAINER=nct
retained_container=nct-pre-fresh
docker_probe() { return 124; }
if hold_named_container_stopped "$CONTAINER"; then exit 41; fi
if hold_all_nct_stopped; then exit 42; fi
exit 0
'''
    result = subprocess.run(["sh", "-c", exercise], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_rendered_create_uses_new_data_exact_image_and_no_old_secrets(tmp_path):
    plan = {
        "contract": "nct-explicit-fresh-install:1",
        "container_name": "nct",
        "image_id": "sha256:" + "a" * 64,
        "new_data": {"type": "volume", "source": "nct-fresh"},
        "runtime": fresh._validate_runtime(
            _write(tmp_path / "inspect.json", runtime_inspect("volume", "nct-old")),
            "nct-old", "volume"
        ),
    }
    script = fresh.render_create(plan, True, "admin", "/private/bootstrap", 30)
    assert "timeout -k 5 30 docker create" in script
    assert "nct-fresh:/data" in script
    assert "nct-old" not in script
    assert "sha256:" + "a" * 64 in script
    assert "NCT_BOOTSTRAP_ADMIN=admin" in script
    assert "NCT_ARKIME" not in script
    assert "must-not-copy" not in script


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_tampered_plan_is_rejected(tmp_path):
    plan = {"contract": "nct-explicit-fresh-install:1", "container_name": "nct"}
    plan["plan_digest"] = fresh._json_digest(plan)
    plan["confirmation"] = f"FRESH-{plan['plan_digest'][:12]}"
    path = _write(tmp_path / "plan.json", plan)
    assert fresh.load_plan(path)["container_name"] == "nct"
    plan["container_name"] = "other"
    _write(path, plan)
    with pytest.raises(fresh.FreshInstallError, match="digest"):
        fresh.load_plan(path)


def test_verify_fresh_requires_only_new_admin_and_no_operator_data(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    db = sqlite3.connect(root / "analyzer.db")
    db.executescript("""
        CREATE TABLE analyst_users (username TEXT, role TEXT, disabled INTEGER);
        CREATE TABLE network_scopes (id TEXT);
        CREATE TABLE scan_runs (id TEXT);
        INSERT INTO analyst_users VALUES ('admin', 'admin', 0);
    """)
    db.commit()
    db.close()
    result = fresh.verify_fresh(root, "admin")
    assert result["ready_for_first_sign_in"] is True

    db = sqlite3.connect(root / "analyzer.db")
    db.execute("INSERT INTO scan_runs VALUES ('old')")
    db.commit()
    db.close()
    with pytest.raises(fresh.FreshInstallError, match="inherited operator data"):
        fresh.verify_fresh(root, "admin")


def test_summary_and_fresh_verification_include_committed_wal_rows(tmp_path):
    live = tmp_path / "live"
    live.mkdir()
    db = sqlite3.connect(live / "analyzer.db")
    db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA wal_autocheckpoint=0;
        CREATE TABLE analyst_users (username TEXT, role TEXT, disabled INTEGER);
        CREATE TABLE scan_runs (id TEXT);
        INSERT INTO analyst_users VALUES ('admin', 'admin', 0);
    """)
    db.commit()
    db.execute("INSERT INTO scan_runs VALUES ('committed-in-wal')")
    db.commit()

    frozen = tmp_path / "frozen"
    frozen.mkdir()
    for name in ("analyzer.db", "analyzer.db-wal", "analyzer.db-shm"):
        source = live / name
        if source.exists():
            (frozen / name).write_bytes(source.read_bytes())
    db.close()

    assert fresh.data_summary(frozen)["counts"]["scan_runs"] == 1
    with pytest.raises(fresh.FreshInstallError, match="inherited operator data"):
        fresh.verify_fresh(frozen, "admin")


def test_host_script_keeps_fresh_install_separate_and_fail_closed():
    content = SCRIPT_PATH.read_text(encoding="utf-8")
    assert "There is no --yes bypass" in content
    assert "--cancel --plan" in content
    assert "intentionally held stopped" in content
    assert "docker volume rm" not in content
    assert "rm -rf" not in content
    assert "--restart=no" in content
    assert "independently extracted backup does not match" in content
    assert "container changed after preview" in content
    assert "data changed after preview" in content
    assert "Fresh NCT is healthy and the new Administrator sign-in was verified" in content
    assert "Rollback source retained" in content
    assert "automatic_network_contact=false" in content
    assert "remove_raw_inspect" in content
    assert "--name \"$HELPER_NAME\"" in content
    assert "helper cleanup could not be proven" in content
    assert "validate-runtime" in content
    assert "automatic rollback could not be verified" in content
    assert "curl -k" not in content


def test_operator_guides_explain_preview_apply_and_rollback_boundary():
    quickstart = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(encoding="utf-8")
    scripts_readme = (ROOT / "scripts" / "README.md").read_text(encoding="utf-8")
    package_readme = (ROOT / "docs" / "RANGE_PACKAGE_SCRIPTS_README.md").read_text(encoding="utf-8")
    built_in = (ROOT / "app" / "how_nct_works_ui.py").read_text(encoding="utf-8")
    for content in (quickstart, scripts_readme, package_readme, built_in):
        assert "nct-fresh-install.sh --container nct" in content
        assert "old" in content.lower() and "rollback" in content.lower()
        assert "new Administrator" in content
    assert "There is no general `--yes` bypass" in quickstart
    assert "first Administrator sign-in" in quickstart
    assert "connector credentials" in quickstart
    assert "automatic collection" in quickstart


def test_host_script_has_valid_posix_shell_syntax():
    result = subprocess.run(["sh", "-n", str(SCRIPT_PATH)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
