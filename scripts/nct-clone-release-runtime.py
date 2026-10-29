#!/usr/bin/env python3
"""Trusted full-package adapter preserving the stopped installation's runtime."""
import argparse
import copy
import http.client
import json
import os
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request


class Docker:
    """Small local-daemon adapter; deliberately independent of recovery/Python 3.9."""

    def command(self, *args):
        return subprocess.check_output(["docker"] + list(args), timeout=180).decode("utf-8")

    def inspect(self, name):
        return json.loads(self.command("container", "inspect", name))[0]

    def exists(self, name):
        return any(name == row["Id"] or "/" + name in row["Names"]
                   for row in self.api("GET", "/containers/json?all=true"))

    def api(self, method, path, body=None):
        connection = http.client.HTTPConnection("localhost", timeout=60)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(60)
        try:
            connection.sock.connect("/var/run/docker.sock")
            payload = None if body is None else json.dumps(body).encode("utf-8")
            connection.request(method, path, payload, {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(1024 ** 2 + 1)
            if response.status not in (200, 201) or len(raw) > 1024 ** 2:
                raise ValueError("Docker refused the bounded runtime operation")
            return json.loads(raw.decode("utf-8"))
        finally:
            connection.close()

    def create(self, name, config):
        return self.api("POST", "/containers/create?name=" + urllib.parse.quote(name), config)["Id"]

    def check_daemon(self):
        if os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock") != "unix:///var/run/docker.sock":
            raise ValueError("Runtime preservation requires the local Docker socket")
        if self.command("info", "--format", "{{.ID}}").strip() != self.api("GET", "/info")["ID"]:
            raise ValueError("Docker CLI and runtime helper address different daemons")


def check_runtime(original):
    host = original["HostConfig"]
    if host.get("AutoRemove") or host.get("VolumesFrom") or host.get("NetworkMode", "default") not in ("default", "bridge"):
        raise ValueError("Shared, custom-network or auto-removing runtime needs a separately qualified adapter")
    networks = original.get("NetworkSettings", {}).get("Networks", {})
    if set(networks) - {"bridge"} or any(
        item.get("IPAMConfig") or item.get("Aliases") or item.get("Links")
        for item in networks.values()
    ):
        raise ValueError("Custom endpoint configuration needs a separately qualified adapter")
    bound_targets = {item.split(":")[1] for item in host.get("Binds", []) if ":" in item}
    bound_targets.update(item["Target"] for item in host.get("Mounts", []) if "Target" in item)
    if any(item.get("Type") == "volume" and item.get("Destination") not in bound_targets
           for item in original.get("Mounts", [])):
        raise ValueError("Implicit volumes need a separately qualified adapter; they must not be replaced with empty volumes")
    if any(binding.get("HostPort") in (None, "", "0")
           for bindings in (host.get("PortBindings") or {}).values() for binding in (bindings or [])):
        raise ValueError("Dynamic port bindings need a separately qualified adapter")
    if host.get("PublishAllPorts"):
        raise ValueError("Automatically published ports need a separately qualified adapter")


def clone(args, engine=None):
    engine = engine or Docker()
    engine.check_daemon()
    original = engine.inspect(args.original_id)
    check_runtime(original)
    context = ssl.create_default_context(cafile=args.ca_file)
    if args.check:
        if original["Id"] != args.original_id:
            raise ValueError("Original container identity changed")
        return original["Id"]
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
    engine.command("update", "--restart=no", original["Id"])
    runtime = engine.create(args.name, config)
    engine.command("start", runtime)
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
    parser.add_argument("--check", action="store_true", help="Check runtime before stopping; do not create or start anything")
    print("Verified replacement container: " + clone(parser.parse_args()))
