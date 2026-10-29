import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("fcntl")
spec = importlib.util.spec_from_file_location("local_helper_host", Path(__file__).parents[1] / "scripts/nct_update_host.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
IMAGE = "sha256:" + "a" * 64


class Engine:
    def __init__(self, failure=None):
        self.failure, self.calls, self.item, self.created = failure, [], None, None

    def command(self, *args, **kwargs):
        self.calls.append(args)
        assert args[0] not in {"run", "pull"} and "--pull=never" not in args
        if args[:2] == ("image", "inspect"):
            if self.failure == "missing":
                raise ValueError("Image missing")
            return json.dumps([{"Id": IMAGE}])
        if args[0] == "start":
            assert kwargs == {"max_output_bytes": 64 * 1024**2}
            self.item["State"] = {"Running": True, "ExitCode": 0}
            if self.failure == "timeout":
                raise ValueError("Bounded timeout")
            self.item["State"] = {"Running": False, "ExitCode": 1 if self.failure == "nonzero" else 0}
            return "verified output"
        if args[0] == "stop":
            self.item["State"]["Running"] = self.failure == "stop"
        if args[0] == "update" and self.failure == "update":
            raise ValueError("Restart-policy update failed")
        if args[0] == "rm":
            self.item = None
        return ""

    def create(self, name, config):
        self.created = copy.deepcopy(config)
        self.item = {"Id": "helper-id", "Image": IMAGE, "State": {"Running": False}}
        if self.failure == "mismatch":
            self.item["Image"] = "sha256:" + "b" * 64
        return "helper-id"

    def inspect(self, identity):
        return copy.deepcopy(self.item)

    def exists(self, name):
        return self.inspect(name)


def host(tmp_path, engine):
    value = module.Host.__new__(module.Host)
    value.root, value.engine = tmp_path, engine
    return value


def test_local_create_pins_image_and_preserves_mount_and_network_restrictions(tmp_path):
    engine = Engine()
    assert host(tmp_path, engine).run_helper("mutable-tag", ["--read-only", "--mount", "type=bind,src=/saved,dst=/data,readonly"], ["check.py"]) == "verified output"
    config = engine.created
    assert config["Image"] == IMAGE and config["Entrypoint"] == ["python"]
    assert config["Env"] == ["PYTHONPATH=/app"] and config["Cmd"] == ["check.py"]
    assert config["HostConfig"] == {"NetworkMode": "none", "ReadonlyRootfs": True, "Mounts": [{"Type": "bind", "Source": "/saved", "Target": "/data", "ReadOnly": True}], "RestartPolicy": {"Name": "no"}}
    assert engine.item is None


@pytest.mark.parametrize("failure", ["missing", "nonzero", "timeout", "stop", "update", "mismatch"])
def test_helper_failures_never_pull_and_cleanup_is_proved(tmp_path, failure):
    engine = Engine(failure)
    if failure == "stop":
        # Simulate an attach timeout followed by a helper that refuses to stop.
        original = engine.command
        def command(*args, **kwargs):
            if args[0] == "start":
                engine.item["State"]["Running"] = True
                raise ValueError("Bounded timeout")
            return original(*args, **kwargs)
        engine.command = command
    with pytest.raises(ValueError):
        host(tmp_path, engine).run_helper(IMAGE, [], ["check.py"])
    if failure == "missing":
        assert engine.created is None and not list(tmp_path.iterdir())
    elif failure == "stop":
        assert engine.item["State"]["Running"] and not any(c[0] == "rm" for c in engine.calls)
    elif failure == "update":
        assert any(c[0] == "stop" for c in engine.calls) and not engine.item["State"]["Running"]
        assert not any(c[0] == "rm" for c in engine.calls)
    elif failure == "mismatch":
        assert not any(c[0] in {"start", "stop", "rm"} for c in engine.calls)
    else:
        assert engine.item is None


@pytest.mark.parametrize("options", [["--privileged"], ["--mount"], ["--mount", "type=volume,src=/saved,dst=/data"], ["--mount", "type=bind,src=/saved,dst=/data,readonly=false"]])
def test_unreviewed_helper_options_refused_before_create(tmp_path, options):
    engine = Engine()
    with pytest.raises(ValueError):
        host(tmp_path, engine).run_helper(IMAGE, options, ["check.py"])
    assert engine.created is None


def test_large_inventory_is_complete_with_helper_bound_but_generic_limit_stays_small():
    command = [sys.executable, "-c", "import sys;sys.stdout.write('x'*(9*1024**2))"]
    with pytest.raises(ValueError, match="limit"):
        module.run(command, timeout=10)
    result = module.run(command, timeout=10, max_output_bytes=64 * 1024**2)
    assert len(result) == 9 * 1024**2


def test_inventory_output_remains_bounded_and_timeout_is_enforced():
    with pytest.raises(ValueError, match="limit"):
        module.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*(65*1024**2))"], timeout=10, max_output_bytes=64 * 1024**2)
    with pytest.raises(ValueError, match="limit"):
        module.run([sys.executable, "-c", "import time;time.sleep(10)"], timeout=0.1, max_output_bytes=64 * 1024**2)
    with pytest.raises(ValueError, match="Invalid"):
        module.run([sys.executable, "-c", "pass"], max_output_bytes=65 * 1024**2)
