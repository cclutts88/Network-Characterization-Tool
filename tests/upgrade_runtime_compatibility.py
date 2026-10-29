"""Run with Python 3.6: exercise the actual helper without third-party packages."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("runtime", Path(__file__).parents[1] / "scripts/nct-clone-release-runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class Engine:
    def check_daemon(self):
        pass

    def inspect(self, name):
        return {"Id": "original", "State": {"Running": False},
                "Config": {"Env": ["CUSTOM=retained", "NCT_BUILD_ID=old"], "Cmd": ["custom"]},
                "HostConfig": {"SecurityOpt": ["seccomp=unconfined"], "Privileged": False,
                               "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 7}}}

    def exists(self, name):
        return False

    def command(self, *args):
        if args[0] == "image":
            return json.dumps([{"Id": "new-image", "Config": {"Env": ["NCT_BUILD_ID=new", "NCT_BUILD_COMMIT=commit"]}}])

    def create(self, name, config):
        assert config["HostConfig"] == self.inspect(name)["HostConfig"]
        assert config["Env"] == ["CUSTOM=retained"]
        assert config["Cmd"] == ["custom"]
        return "candidate"


class Response:
    def __enter__(self):
        import io
        return io.StringIO(json.dumps({"build_id": "new", "build_commit": "commit", "healthy": True}))

    def __exit__(self, *args):
        pass


engine = Engine()
args = SimpleNamespace(original_id="original", image="new", name="nct", url="https://test", ca_file="ca", check=False)
opener = SimpleNamespace(open=lambda *a, **kw: Response())
with patch.object(runtime.ssl, "create_default_context"), patch.object(runtime.urllib.request, "build_opener", return_value=opener):
    assert runtime.clone(args, engine) == "candidate"
    args.check = True
    assert runtime.clone(args, engine) == "original"
print("Old-Python runtime preservation and nonmutating preflight passed")
