"""Real HTTPS/bootstrap/service acceptance on a disposable Docker fixture.

Only systemctl is substituted: the generated service's actual Python entry point
runs as a separate process. A real systemd boot remains a deployment acceptance.
"""
from __future__ import annotations
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--console-image", help="Separate independently pinned console image to qualify")
    parser.add_argument("--exercise-resume", action="store_true")
    args = parser.parse_args()
    root = args.root
    if root.name != "_data" or not root.parent.name.startswith("nct-update-acceptance-") or root.parent.parent != Path("/var/lib/docker/volumes"):
        raise ValueError("Use dedicated persistent acceptance storage")
    root.mkdir(exist_ok=True)
    bootstrap = root / "bootstrap"
    bootstrap.mkdir()
    for name in ("install_nct_recovery.py", "finish_nct_recovery.py", "nct_update_host.py", "nct-range-data-check.py", "nct_update_work.py"):
        shutil.copyfile(Path("/workspace/scripts") / name, bootstrap / name)
    sys.path.insert(0, str(bootstrap))
    import nct_update_host as module
    import install_nct_recovery as installer
    authority_id = Path("/etc/hostname").read_text().strip()
    class HostHarnessDocker(module.Docker):
        def inventory(self):
            return [item for item in super().inventory() if not item["Id"].startswith(authority_id)]
    installer.Docker = HostHarnessDocker
    engine = HostHarnessDocker()
    tls, data = root / "tls", root / "data"
    tls.mkdir()
    data.mkdir()
    cert, key = tls / "server.crt", tls / "server.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=host.docker.internal",
        "-addext", "subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    name = "nct-install-test-" + secrets.token_hex(6)
    password = secrets.token_urlsafe(18)
    image = json.loads(engine.command("image", "inspect", "nct-update-acceptance:old"))[0]["Id"]
    engine.command("run", "-d", "--name", name, "--restart", "on-failure:3", "-p", "127.0.0.1:18153:8445",
        "-v", f"{data}:/data", "-v", f"{tls}:/run/tls:ro", "-e", "NCT_AUTH_MODE=local", "-e", "NCT_COOKIE_SECURE=1",
        "-e", "NCT_BOOTSTRAP_ADMIN=preview-operator", "-e", "NCT_BOOTSTRAP_PASSWORD=" + password,
        image, "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8445", "--ssl-certfile", "/run/tls/server.crt", "--ssl-keyfile", "/run/tls/server.key")
    configuration = {"container": name, "data_dir": str(data), "state_dir": str(root / "preflight"), "maintenance_lock": str(root / "deployment/maintenance.lock"),
        "application_url": "https://host.docker.internal:18153", "ca_file": str(cert)}
    host = module.Host(configuration, engine)
    host.wait_url(configuration["application_url"] + "/health/readiness", lambda value: value.get("healthy") is True)
    # Bootstrap the real copied host service as a separate process. The sole test
    # substitution removes this administrative fixture container from peer scans.
    installed = root / "installed"
    wrapper = root / "service-acceptance.py"
    wrapper.write_text("import sys\nsys.path.insert(0," + repr(str(installed)) + ")\nimport nct_update_host as m\nclass D(m.Docker):\n def inventory(self):\n  return [x for x in super().inventory() if not x['Id'].startswith(" + repr(authority_id) + ")]\nm.Docker=D\nm.main()\n")
    service_command = [sys.executable, str(wrapper), "--config", str(installed / "config.json")]
    service = None
    real_run = subprocess.run
    log = (root / "service.log").open("wb")
    def system_service(command, *arguments, **keywords):
        nonlocal service
        if command[0] == "systemctl":
            if "enable" in command:
                service = subprocess.Popen(service_command, stdout=log, stderr=log)
            return subprocess.CompletedProcess(command, 0)
        return real_run(command, *arguments, **keywords)
    installer.subprocess.run = system_service
    console_image = args.console_image or image
    console_id = json.loads(engine.command("image", "inspect", console_image))[0]["Id"]
    if args.console_image and console_id == image:
        raise ValueError("Separate-console acceptance requires a distinct immutable image")
    install_args = argparse.Namespace(container=name, console_container=name + "-console", console_image=console_id,
        application_url=configuration["application_url"], console_url="https://host.docker.internal:18154", bind_address="127.0.0.1",
        data_dir=data, state_dir=root / "state", install_dir=installed, cert_file=cert, key_file=key, ca_file=cert, enable_container=True)
    if args.exercise_resume:
        real_host = installer.Host
        class InterruptedHost(real_host):
            def backup(self, operation):
                raise ValueError("Injected interruption before backup")
        installer.Host = InterruptedHost
        try:
            installer.install(install_args)
        except ValueError as exc:
            assert str(exc) == "Injected interruption before backup", str(exc)
        else:
            raise AssertionError("Expected interruption did not occur")
        installer.Host = real_host
        installed_host = real_host(json.loads((installed / "config.json").read_text()), engine)
        interrupted_id = installed_host.read()["id"]
        assert installed_host.read()["phase"] == "awaiting_restore_sign_in"
        installed_host.confirm("preview-operator", password, "host-installer")
        import finish_nct_recovery as continuation
        original = installed_host.target()
        build = dict(v.split("=", 1) for v in original["Config"]["Env"] if "=" in v)
        continuation.finish(installed_host, image, console_id, build["NCT_BUILD_ID"], build["NCT_BUILD_COMMIT"], cert, key)
        current = installed_host.read()
        assert current["id"] != interrupted_id and current["prior_operation_id"] == interrupted_id
        assert current["backup_verified"] and current["evidence_verified"]
        receipt = json.loads((root / "state" / interrupted_id / "reconciled-operation.json").read_text())
        assert receipt["phase"] == "restored" and receipt["controller_sign_in_verified"]
    else:
        installer.install(install_args)
    print("One-time installer completed through real HTTPS and the independent service.", flush=True)
    assert engine.inspect(name + "-console")["Image"] == console_id
    context = ssl.create_default_context(cafile=str(cert))
    cookies = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(cookies), urllib.request.ProxyHandler({}))
    def request(path, body=None, *, console=False):
        url = "https://host.docker.internal:" + ("18154" if console else "18153") + path
        with browser.open(urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "X-NCT-Recovery": "1"}), timeout=120) as response:
            return json.load(response)
    request("/api/auth/login", {"username": "preview-operator", "password": password})
    handoff = request("/api/updates/launch", {})
    code = handoff["url"].split("#handoff=")[1]
    request("/api/exchange", {"code": code}, console=True)
    assert request("/api/status", console=True)["operation"]["phase"] == "awaiting_sign_in"
    request("/api/verify-sign-in", {"username": "preview-operator", "password": password}, console=True)
    state = request("/api/status", console=True)["operation"]
    assert state["phase"] == "complete" and state["controller_sign_in_verified"]
    assert not (data / "recovery/update-maintenance.json").exists()
    request("/api/close", {}, console=True)
    for _ in range(20):
        if not engine.inspect(name + "-console")["State"]["Running"]:
            break
        time.sleep(1)
    assert not engine.inspect(name + "-console")["State"]["Running"]
    assert all(mount["Destination"] != "/var/run/docker.sock" for mount in engine.inspect(name)["Mounts"])
    assert all(mount["Destination"] not in {"/data", "/var/run/docker.sock"} for mount in engine.inspect(name + "-console")["Mounts"])
    service.terminate()
    service.wait(timeout=10)
    service = subprocess.Popen(service_command, stdout=log, stderr=log)
    time.sleep(1)
    code_output = subprocess.check_output(service_command + ["--access-code"], text=True)
    access_code = code_output.split("One-use recovery code (expires in 2 minutes): ")[1].strip()
    request("/api/exchange", {"code": access_code}, console=True)
    assert request("/api/status", console=True)["operation"]["id"] == state["id"]
    request("/api/close", {}, console=True)
    for _ in range(20):
        if not engine.inspect(name + "-console")["State"]["Running"]:
            break
        time.sleep(1)
    assert not engine.inspect(name + "-console")["State"]["Running"]
    module.save(root / "installer-acceptance-result.json", {"result": "pass", "https": True, "independent_service_restart": True,
        "console_image_id": console_id, "distinct_console_image": console_id != image,
        "interrupted_install_continuation": args.exercise_resume,
        "on_demand_console_stop": True, "docker_socket_absent_from_web_containers": True, "systemd_boot_tested": False})
    print("PASS: HTTPS handoff, bootstrap account verification, console stop, durable service restart and host-code recovery.", flush=True)
    service.terminate()
    service.wait(timeout=10)
    engine.command("update", "--restart=no", name)
    engine.command("stop", name)


if __name__ == "__main__":
    main()
