"""Behavioral checks for the normal terminal upgrade's runtime adapter."""
import copy
import importlib.util
import json
import os
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/nct-clone-release-runtime.py"
spec = importlib.util.spec_from_file_location("upgrade_runtime", SCRIPT)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class Engine:
    def __init__(self, security=None):
        self.original = {
            "Id": "original", "State": {"Running": False},
            "Config": {"Hostname": "temporary", "Domainname": "",
                       "Env": ["NCT_BUILD_ID=old", "NCT_BUILD_COMMIT=old", "NCT_APP_VERSION=old",
                               "NCT_AUTH_MODE=local", "NCT_BOOTSTRAP_PASSWORD_FILE=/secret", "CUSTOM=preserve"],
                       "Cmd": ["uvicorn", "custom:app"], "Entrypoint": ["/entry"],
                       "User": "1000", "WorkingDir": "/custom", "Labels": {"owner": "analyst"}},
            "HostConfig": {"SecurityOpt": security, "Privileged": False, "CapAdd": ["NET_RAW"],
                           "NetworkMode": "default", "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 7},
                           "Binds": ["/data:/data", "/empty-secret:/secret:ro"],
                           "PortBindings": {"8445/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8445"}]},
                           "Memory": 123456, "PidsLimit": 120},
            "NetworkSettings": {"Networks": {"bridge": {"IPAMConfig": None, "Aliases": None}}},
        }
        self.calls = []

    def check_daemon(self):
        self.calls.append("daemon")

    def inspect(self, name):
        return copy.deepcopy(self.original)

    def exists(self, name):
        return False

    def command(self, *args):
        self.calls.append(args)
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"Id": "sha256:new", "Config": {"Env": ["NCT_BUILD_ID=new", "NCT_BUILD_COMMIT=commit"]}}])
        return ""

    def create(self, name, config):
        self.created = config
        self.calls.append("create")
        return "candidate"


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        import io
        return io.StringIO(json.dumps(self.payload))

    def __exit__(self, *args):
        pass


def args(check=False):
    return SimpleNamespace(original_id="original", name="nct", image="release", url="https://127.0.0.1:8445", ca_file="ca", check=check)


@pytest.mark.parametrize("security", [None, ["seccomp=unconfined"], ["no-new-privileges:true"]])
def test_exact_runtime_preserved_without_inventing_permissions(security):
    engine = Engine(security)
    opener = SimpleNamespace(open=lambda url, **kwargs: Response(
        {"healthy": True} if url.endswith("readiness") else {"build_id": "new", "build_commit": "commit"}))
    with patch.object(runtime.ssl, "create_default_context"), patch.object(runtime.urllib.request, "build_opener", return_value=opener):
        assert runtime.clone(args(), engine) == "candidate"
    assert engine.created["HostConfig"] == engine.original["HostConfig"]
    assert engine.created["Image"] == "sha256:new"
    for key in ("Cmd", "Entrypoint", "User", "WorkingDir", "Labels"):
        assert engine.created[key] == engine.original["Config"][key]
    assert engine.created["Env"] == ["NCT_AUTH_MODE=local", "NCT_BOOTSTRAP_PASSWORD_FILE=/secret", "CUSTOM=preserve"]
    assert "Hostname" not in engine.created
    assert engine.calls.index(("update", "--restart=no", "original")) < engine.calls.index("create")


@pytest.mark.parametrize("change", ["shared", "auto", "custom", "alias", "ip", "extra", "volume", "dynamic", "publish"])
def test_unsupported_runtime_rejected_in_nonmutating_preflight(change):
    engine = Engine()
    if change == "shared":
        engine.original["HostConfig"]["VolumesFrom"] = ["other"]
    elif change == "auto":
        engine.original["HostConfig"]["AutoRemove"] = True
    elif change == "custom":
        engine.original["HostConfig"]["NetworkMode"] = "custom"
    elif change == "extra":
        engine.original["NetworkSettings"]["Networks"]["extra"] = {}
    elif change == "volume":
        engine.original["Mounts"] = [{"Type": "volume", "Destination": "/anonymous"}]
    elif change == "dynamic":
        engine.original["HostConfig"]["PortBindings"] = {"8445/tcp": [{"HostPort": ""}]}
    elif change == "publish":
        engine.original["HostConfig"]["PublishAllPorts"] = True
    else:
        engine.original["NetworkSettings"]["Networks"]["bridge"]["Aliases" if change == "alias" else "IPAMConfig"] = ["custom"]
    with pytest.raises(ValueError, match="qualified adapter"):
        runtime.clone(args(check=True), engine)
    assert engine.calls == ["daemon"]


def test_live_preflight_does_not_stop_or_change_original():
    engine = Engine()
    engine.original["State"]["Running"] = True
    with patch.object(runtime.ssl, "create_default_context"):
        assert runtime.clone(args(check=True), engine) == "original"
    assert engine.calls == ["daemon"]


def test_daemon_mismatch_and_remote_socket_are_refused(monkeypatch):
    engine = runtime.Docker()
    monkeypatch.setattr(engine, "command", lambda *a: "cli-daemon")
    monkeypatch.setattr(engine, "api", lambda *a: {"ID": "different-daemon"})
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    with pytest.raises(ValueError, match="different daemons"):
        engine.check_daemon()
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote:2375")
    with pytest.raises(ValueError, match="local Docker socket"):
        engine.check_daemon()


def test_failed_readiness_never_claims_acceptance_or_restarts_original():
    engine = Engine()
    opener = SimpleNamespace(open=lambda *a, **kw: Response({"build_id": "old", "healthy": False}))
    with patch.object(runtime.ssl, "create_default_context"), patch.object(runtime.urllib.request, "build_opener", return_value=opener), patch.object(runtime.time, "sleep"):
        with pytest.raises(ValueError, match="restore its verified backup"):
            runtime.clone(args(), engine)
    assert ("start", "original") not in engine.calls


def test_upgrade_requires_preservation_before_stopping_and_restores_restart_policy():
    source = (SCRIPT.parent / "nct-upgrade.sh").read_text()
    assert source.index('"$RUNTIME_CLONE" --check') < source.index('docker stop "$CONTAINER"')
    assert 'NCT_UPGRADE_ACCOUNT_COUNT="$account_count" sh "$start_script"' not in source
    assert 'docker update --restart="$original_restart_policy" "$CONTAINER"' in source


@pytest.mark.skipif(os.name != "posix", reason="POSIX recovery harness")
def test_failed_upgrade_restores_verified_bytes_before_original_policy_and_start(tmp_path):
    data = tmp_path / "data"
    backups = tmp_path / "backups"
    data.mkdir()
    backups.mkdir()
    (data / "evidence").write_text("retained evidence")
    archive = backups / "cold.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(data, arcname="data")
    import hashlib
    Path(str(archive) + ".sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + str(archive) + "\n")
    before = backups / "before"
    before.write_text("retained evidence")
    (data / "evidence").write_text("candidate changes")
    source = (SCRIPT.parent / "nct-upgrade.sh").read_text()
    start_original = source[source.index("start_original_if_needed() {"):source.index("was_running=$(docker inspect")]
    restore = source[source.index("restore_original() {"):source.index("trap restore_original EXIT")]
    mock = '''
docker() {
    printf '%s\\n' "$*" >> "$LOG"
    if [ "$1" = inspect ] && [ "$2" = --format ]; then printf false; fi
}
curl() { printf '{"status":"ok"}'; }
verify_rollback_identity() { return 0; }
snapshot() { cat "$DATA_DIR/evidence" > "$1"; }
'''
    harness = mock + start_original + restore + '\ntrap restore_original EXIT\nfalse\n'
    result = subprocess.run(["sh", "-c", harness], capture_output=True, text=True, env={**os.environ,
        "DATA_DIR": str(data), "PERSIST_ROOT": str(tmp_path), "BACKUP_DIR": str(backups),
        "backup": str(archive), "before": str(before), "LOG": str(tmp_path / "docker.log"),
        "CONTAINER": "nct", "rollback": "retained-original", "timestamp": "fixture",
        "candidate_may_have_written": "yes", "backup_ready": "yes", "upgrade_complete": "no",
        "was_running": "true", "original_restart_policy": "on-failure:7", "RANGE_IP": "127.0.0.1", "original_host_port": "8445"})
    assert result.returncode == 1
    assert "verified pre-upgrade data were restored" in result.stderr
    assert (data / "evidence").read_text() == "retained evidence"
    assert (tmp_path / "failed-upgrade-data-fixture/evidence").read_text() == "candidate changes"
    log = (tmp_path / "docker.log").read_text()
    assert log.index("update --restart=no nct") < log.index("stop nct")
    assert log.index("rename retained-original nct") < log.index("update --restart=on-failure:7 nct") < log.index("start nct")


@pytest.mark.skipif(os.name != "posix", reason="POSIX recovery harness")
@pytest.mark.parametrize("bad_inventory", [False, True])
def test_later_rollback_fences_candidate_and_restores_policy_only_after_verified_data(tmp_path, bad_inventory):
    data, backups = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    backups.mkdir()
    (data / "evidence").write_text("original evidence")
    backup = backups / "cold.tar.gz"
    with tarfile.open(backup, "w:gz") as archive:
        archive.add(data, arcname="data")
    import hashlib
    checksum = Path(str(backup) + ".sha256")
    checksum.write_text(hashlib.sha256(backup.read_bytes()).hexdigest() + "  " + str(backup) + "\n")
    before = backups / "before"
    before.write_text("wrong inventory" if bad_inventory else "original evidence")
    (data / "evidence").write_text("later evidence")
    source = (SCRIPT.parent / "nct-rollback-upgrade.sh").read_text()
    body = source[source.index('say "Stopping the candidate'):source.index('if ! health=$(curl')]
    harness = '''set -eu
docker() { printf '%s\\n' "$*" >> "$LOG"; if [ "$1" = inspect ]; then printf false; fi; }
say() { :; }
die() { echo "$*" >&2; exit 1; }
check_active() { :; }
snapshot() { cat "$DATA_DIR/evidence" > "$1"; }
''' + body
    result = subprocess.run(["sh", "-c", harness], capture_output=True, text=True, env={**os.environ,
        "DATA_DIR": str(data), "PERSIST_ROOT": str(tmp_path), "backup": str(backup), "checksum": str(checksum),
        "before": str(before), "restored_inventory": str(backups / "restored"), "CONTAINER": "nct",
        "failed_container": "failed", "failed_data": str(tmp_path / "preserved"), "rollback": "old",
        "rollback_restart_policy": "on-failure:7", "LOG": str(tmp_path / "calls")})
    calls = (tmp_path / "calls").read_text()
    assert calls.index("update --restart=no nct") < calls.index("stop nct") < calls.index("rename nct failed")
    assert (tmp_path / "preserved/evidence").read_text() == "later evidence"
    assert (data / "evidence").read_text() == "original evidence"
    assert (result.returncode == 0) is not bad_inventory
    assert ("update --restart=on-failure:7 nct" in calls) is not bad_inventory
    assert ("start nct" in calls) is not bad_inventory


def test_restart_receipt_and_built_in_upgrade_explanation():
    upgrade = (SCRIPT.parent / "nct-upgrade.sh").read_text()
    rollback = (SCRIPT.parent / "nct-rollback-upgrade.sh").read_text()
    assert "rollback_restart_policy=%s" in upgrade
    assert "Older receipt has no restart policy" in rollback
    assert "Receipt restart policy is invalid" in rollback
    guide = (SCRIPT.parents[1] / "app/how_nct_works_ui.py").read_text()
    assert "Preserving settings during terminal upgrades" in guide
    assert "Python 3.6 or newer" in guide


@pytest.mark.skipif(os.name != "posix", reason="POSIX recovery harness")
def test_unhealthy_old_container_is_stopped_even_when_restart_update_fails(tmp_path):
    source = (SCRIPT.parent / "nct-rollback-upgrade.sh").read_text()
    body = source[source.index("stop_unhealthy_previous() {"):source.index('[ "$(id -u)"')]
    harness = '''set -eu
die() { echo "$*" >&2; exit 1; }
docker() {
    printf '%s\\n' "$*" >> "$LOG"
    case "$1" in update) return 1;; inspect) printf false;; esac
}
''' + body + '\nstop_unhealthy_previous "Unhealthy."\n'
    result = subprocess.run(["sh", "-c", harness], capture_output=True, text=True,
                            env={**os.environ, "LOG": str(tmp_path / "calls"), "CONTAINER": "nct"})
    assert result.returncode == 1
    assert "was stopped, but its restart policy could not be disabled" in result.stderr
    calls = (tmp_path / "calls").read_text()
    assert "stop nct" in calls and "inspect --format" in calls
