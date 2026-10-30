import copy
from contextlib import contextmanager
import importlib
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
continuation = importlib.import_module("finish_nct_recovery")
installer = importlib.import_module("install_nct_recovery")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    cert, key = tmp_path / "cert", tmp_path / "key"
    cert.write_text("certificate"); key.write_text("key")
    root = tmp_path / "state"
    root.mkdir()
    previous = {"id": "d" * 32, "kind": "enable_console", "phase": "restored", "controller_sign_in_verified": True}
    (root / previous["id"]).mkdir()
    original = {"Id": "c" * 64, "Image": "sha256:" + "a" * 64, "State": {"Running": True},
        "Config": {"Env": ["NCT_AUTH_MODE=local", "NCT_BUILD_ID=test", "NCT_BUILD_COMMIT=" + "e" * 40]},
        "HostConfig": {"Binds": [], "RestartPolicy": {"Name": "unless-stopped"}}, "Mounts": []}
    console = {"Image": "sha256:" + "b" * 64, "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"]},
        "Mounts": [{"Destination": dest, "Source": str(src), "Type": "bind", "RW": rw} for dest, src, rw in (
            ("/run/nct-recovery", root / "sockets/control", False), ("/staging", root / "spool", True),
            ("/run/tls/server.crt", cert, False), ("/run/tls/server.key", key, False))]}
    host = Mock(root=root, data=tmp_path / "data", config={"launch_socket": str(root / "sockets/launch/launch.sock"), "console_container": "console", "console_image_id": console["Image"], "container": "nct"})
    host.read.return_value = previous
    host.target.return_value = original
    host.engine.inspect.return_value = console
    host.exclusive = contextmanager(lambda: (yield))
    monkeypatch.setattr(continuation.subprocess, "run", Mock())
    arguments = (original["Image"], console["Image"], "test", "e" * 40, cert, key)
    return host, original, console, previous, arguments


@pytest.mark.parametrize("change", [
    lambda c: c["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
    lambda c: c["HostConfig"].update(SecurityOpt=["no-new-privileges:true", "seccomp=unconfined"]),
    lambda c: c["HostConfig"].update(PidMode="host"),
    lambda c: c["HostConfig"].update(IpcMode="host"),
    lambda c: c["HostConfig"].update(NetworkMode="host"),
    lambda c: c["HostConfig"].update(Devices=[{"PathOnHost": "/dev/sda"}]),
    lambda c: c["Mounts"].append({"Source": "/var/lib", "Destination": "/extra", "Type": "bind", "RW": False}),
    lambda c: c["Mounts"][0].update(RW=True),
    lambda c: c["Mounts"][1].update(Source="/var/lib"),
    lambda c: c["Mounts"][2].update(Type="volume"),
])
def test_widened_console_is_rejected_before_mutation(setup, change):
    host, _, console, _, args = setup
    change(console)
    with pytest.raises(ValueError):
        continuation.finish(host, *args)
    host.launch.assert_not_called()
    host.stop_exact.assert_not_called()


@pytest.mark.parametrize("change", ["operation", "runtime", "socket", "unverified"])
def test_rechecks_under_lock_before_new_journal_or_stop(setup, change):
    host, original, _, previous, args = setup
    @contextmanager
    def locked():
        if change == "operation":
            host.read.return_value = {**previous, "id": "f" * 32}
        elif change == "runtime":
            replacement = copy.deepcopy(original)
            replacement["HostConfig"]["Binds"].append("/extra:/extra")
            host.target.return_value = replacement
        elif change == "socket":
            host.target.return_value = {**original, "Mounts": [{"Destination": "/run/nct-update"}]}
        else:
            host.read.return_value = {**previous, "controller_sign_in_verified": False}
        yield
    host.exclusive = locked
    with pytest.raises(ValueError):
        continuation.finish(host, *args)
    host.phase.assert_not_called()
    host.stop_exact.assert_not_called()
    assert not (host.root / previous["id"] / "reconciled-operation.json").exists()


def test_unverified_previous_operation_never_launches(setup):
    host, _, _, previous, args = setup
    previous["controller_sign_in_verified"] = False
    with pytest.raises(ValueError, match="verify"):
        continuation.finish(host, *args)
    host.launch.assert_not_called()


@pytest.mark.parametrize("change", ["order", "source", "rw", "type", "extra", "duplicate"])
def test_mount_order_is_not_a_change_but_full_records_are_checked(setup, monkeypatch, change):
    host, original, _, _, args = setup
    original["Mounts"] = [
        {"Destination": "/data", "Source": str(host.data), "Type": "bind", "RW": True},
        {"Destination": "/run/tls/server.crt", "Source": str(args[-2]), "Type": "bind", "RW": False},
    ]
    replacement = copy.deepcopy(original)
    replacement["Mounts"].reverse()
    if change == "source": replacement["Mounts"][0]["Source"] = "/other"
    if change == "rw": replacement["Mounts"][0]["RW"] = True
    if change == "type": replacement["Mounts"][0]["Type"] = "volume"
    if change == "extra": replacement["Mounts"].append({"Destination": "/extra", "Source": "/extra", "Type": "bind", "RW": False})
    if change == "duplicate": replacement["Mounts"].append(copy.deepcopy(replacement["Mounts"][0]))
    def transaction(h, initial, container, **kw):
        with h.exclusive():
            h.target.return_value = replacement
            kw["locked_guard"]()
        return "retained"
    monkeypatch.setattr(continuation, "enable_console", transaction)
    if change == "order":
        assert continuation.finish(host, *args) == "retained"
    else:
        with pytest.raises(ValueError, match="changed"):
            continuation.finish(host, *args)
    host.phase.assert_not_called()
    host.stop_exact.assert_not_called()
