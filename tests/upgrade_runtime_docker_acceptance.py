"""Disposable real-daemon acceptance; run in the Docker-equipped validation image."""
import copy
import importlib.util
import json
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("runtime", Path(__file__).parents[1] / "scripts/nct-clone-release-runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
engine = runtime.Docker()
image = "network-characterization-tool:0.16.0-range-test-20261027-recovery-r1"


class Response:
    def __enter__(self):
        import io
        return io.StringIO(json.dumps({"build_id": build["NCT_BUILD_ID"], "build_commit": build["NCT_BUILD_COMMIT"], "healthy": True}))

    def __exit__(self, *args):
        pass


build = dict(item.split("=", 1) for item in json.loads(engine.command("image", "inspect", image))[0]["Config"]["Env"] if "=" in item)
for security in (None, ["seccomp=unconfined"]):
    token = uuid.uuid4().hex[:12]
    old_name, new_name = "nct-runtime-old-" + token, "nct-runtime-new-" + token
    volume = "nct-runtime-volume-" + token
    engine.command("volume", "create", "--label", "nct.test=runtime-preservation", volume)
    try:
        config = {"Image": image, "Cmd": ["python", "-c", "import time; time.sleep(180)"],
                  "Env": ["NCT_BUILD_ID=stale", "CUSTOM=preserved"], "Labels": {"nct.test": token},
                  "HostConfig": {"NetworkMode": "bridge", "SecurityOpt": security, "Privileged": False,
                                 "CapAdd": ["NET_RAW"], "Binds": [volume + ":/custom-data"],
                                 "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 7}}}
        old_id = engine.create(old_name, config)
        original = engine.inspect(old_id)
        args = SimpleNamespace(original_id=old_id, image=image, name=new_name, url="https://test", ca_file="ca", check=True)
        with patch.object(runtime.ssl, "create_default_context"), patch.object(runtime.urllib.request, "build_opener", return_value=SimpleNamespace(open=lambda *a, **kw: Response())):
            assert runtime.clone(args, engine) == old_id
            args.check = False
            new_id = runtime.clone(args, engine)
        replacement = engine.inspect(new_id)
        for key in ("SecurityOpt", "Privileged", "CapAdd", "Binds", "RestartPolicy", "NetworkMode"):
            assert replacement["HostConfig"][key] == original["HostConfig"][key], key
        assert replacement["Config"]["Cmd"] == original["Config"]["Cmd"]
        env = dict(value.split("=", 1) for value in replacement["Config"]["Env"])
        assert env["CUSTOM"] == "preserved" and env["NCT_BUILD_ID"] == build["NCT_BUILD_ID"]
        assert engine.inspect(old_id)["HostConfig"]["RestartPolicy"]["Name"] == "no"
        assert replacement["State"]["Running"]
        print("Real Docker runtime preservation passed:", security)
    finally:
        for name in (new_name, old_name):
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        engine.command("volume", "rm", volume)
