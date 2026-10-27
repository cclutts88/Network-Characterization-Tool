#!/usr/bin/env python3
"""Trusted full-package adapter preserving the stopped installation's runtime."""
import argparse
import copy
import json
import ssl
import time
import urllib.request
from nct_update_host import Docker


def clone(args, engine=None):
    engine = engine or Docker()
    original = engine.inspect(args.original_id)
    if original["Id"] != args.original_id or original["State"]["Running"] or engine.exists(args.name):
        raise ValueError("The exact retained original must be stopped and its public name free")
    image = json.loads(engine.command("image", "inspect", args.image))[0]
    env = dict(value.split("=", 1) for value in image["Config"]["Env"] if "=" in value)
    config = copy.deepcopy(original["Config"])
    config.pop("Hostname", None)
    config.pop("Domainname", None)
    config["Image"] = image["Id"]
    config["Env"] = [value for value in config.get("Env", []) if not value.startswith(("NCT_BUILD_ID=", "NCT_BUILD_COMMIT=", "NCT_APP_VERSION="))]
    config["HostConfig"] = copy.deepcopy(original["HostConfig"])
    host = config["HostConfig"]
    if host.get("AutoRemove") or host.get("VolumesFrom") or host.get("NetworkMode", "").startswith("container:"):
        raise ValueError("Shared or auto-removing runtime needs a separately qualified adapter")
    engine.command("update", "--restart=no", original["Id"])
    runtime = engine.create(args.name, config)
    engine.command("start", runtime)
    context = ssl.create_default_context(cafile=args.ca_file)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.ProxyHandler({}))
    last = None
    for _ in range(90):
        try:
            with opener.open(args.url + "/health", timeout=3) as response:
                health = json.load(response)
            with opener.open(args.url + "/health/readiness", timeout=3) as response:
                readiness = json.load(response)
            if health.get("build_id") == env["NCT_BUILD_ID"] and health.get("build_commit") == env["NCT_BUILD_COMMIT"] and readiness.get("healthy") is True:
                return runtime
        except (OSError, ValueError) as exc:
            last = type(exc).__name__
        time.sleep(1)
    raise ValueError("Replacement did not pass exact-build HTTPS readiness; the caller must restore its verified backup: " + str(last))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-id", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca-file", required=True)
    print("Verified replacement container: " + clone(parser.parse_args()))
