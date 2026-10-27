"""Real staged-package retained-data/bootstrap acceptance; no production targets.

Substitutions: administrative fixture excluded from peer inspection, systemctl
starts the real copied service as a process, and ss checks use Docker admission.
All application/backup/upgrade/CA/HTTPS/account operations are real.
"""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    if root.name != "_data" or not root.parent.name.startswith("nct-full-package-acceptance-") or root.parent.parent != Path("/var/lib/docker/volumes"):
        raise ValueError("Dedicated disposable test volume required")
    root.mkdir(exist_ok=True)
    package = root / "package"
    shutil.copytree(args.package, package)
    sys.path.insert(0, "/workspace/scripts")
    from build_nct_range_package import verify_manifest
    from nct_update_host import Docker, Host
    tested = verify_manifest(package)
    release = json.loads((package / "release.json").read_text())
    engine = Docker()
    name = "nct-full-package-" + secrets.token_hex(6)
    console_name = name + "-console"
    authority = Path("/etc/hostname").read_text().strip()
    gateway = socket.gethostbyname("host.docker.internal")
    persist, installed = root / "persist", root / "installed"
    data = persist / "data"
    data.mkdir(parents=True)
    tls = persist / "tls-material"
    subprocess.run(["sh", str(package / "scripts/setup-lab-https.sh"), gateway, str(tls)], check=True)
    password = secrets.token_urlsafe(20)
    bootstrap = root / "retained-bootstrap"
    bootstrap.write_text(password)
    os.chmod(bootstrap, 0o600)
    original_id = engine.command("run", "-d", "--name", name, "--restart", "on-failure:3", "--cap-add", "NET_RAW",
        "-p", "127.0.0.1:18159:8445", "-v", f"{data}:/data", "-v", f"{tls}/tls/nct-server.crt:/run/tls/nct-server.crt:ro",
        "-v", f"{tls}/tls/nct-server.key:/run/tls/nct-server.key:ro", "-v", f"{bootstrap}:/run/retained-bootstrap:ro",
        "-e", "NCT_AUTH_MODE=local", "-e", "NCT_COOKIE_SECURE=1", "-e", "NCT_BOOTSTRAP_ADMIN=package-operator",
        "-e", "NCT_BOOTSTRAP_PASSWORD_FILE=/run/retained-bootstrap", "-e", "NCT_PACKAGE_PRESERVE_ME=retained-setting",
        "network-characterization-tool:0.16.0-range-test-20261025-phase5-r1", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8445",
        "--ssl-certfile", "/run/tls/nct-server.crt", "--ssl-keyfile", "/run/tls/nct-server.key")
    app_url, console_url = f"https://{gateway}:18159", f"https://{gateway}:18160"
    probe = Host({"state_dir": str(root / "probe"), "data_dir": str(data), "application_url": app_url,
        "ca_file": str(tls / "certs/nct-lab-root.crt")})
    probe.wait_url(app_url + "/health/readiness", lambda value: value.get("healthy") is True)
    context = ssl.create_default_context(cafile=str(tls / "certs/nct-lab-root.crt"))
    cookies = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(cookies), urllib.request.ProxyHandler({}))
    def request(path, body=None, console=False):
        with browser.open(urllib.request.Request((console_url if console else app_url) + path,
            data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json", "X-NCT-Recovery": "1"}), timeout=180) as response:
            return json.load(response)
    request("/api/auth/login", {"username": "package-operator", "password": password})
    xml = b'<nmaprun scanner="nmap" start="100"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><runstats><finished time="101" exit="success"/></runstats></nmaprun>'
    boundary = "nct-package-fixture"
    body = b'--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="file"; filename="retained.xml"\r\nContent-Type: application/xml\r\n\r\n' + xml + b'\r\n--' + boundary.encode() + b'--\r\n'
    with browser.open(urllib.request.Request(app_url + "/api/import", data=body, headers={"Content-Type": "multipart/form-data; boundary=" + boundary}), timeout=30) as response:
        imported = json.load(response)
    bootstrap.write_text("")  # Protected empty legacy mount must survive both replacements.
    print("Exact previous release booted over issuing-CA verified HTTPS; existing account and evidence created.", flush=True)
    bin_dir, shim = root / "bin", root / "shim"
    bin_dir.mkdir()
    shim.mkdir()
    service_log = root / "service.log"
    service = root / "service.py"
    service.write_text("import sys\nsys.path.insert(0," + repr(str(installed)) + ")\nimport nct_update_host as m\nclass D(m.Docker):\n def inventory(self):\n  return [x for x in super().inventory() if not x['Id'].startswith(" + repr(authority) + ")]\nm.Docker=D\nm.main()\n")
    (shim / "sitecustomize.py").write_text("import sys\nsys.path.insert(0," + repr(str(package / "scripts")) + ")\nimport nct_update_host as m\nclass D(m.Docker):\n def inventory(self):\n  return [x for x in super().inventory() if not x['Id'].startswith(" + repr(authority) + ")]\nm.Docker=D\n")
    systemctl = bin_dir / "systemctl"
    systemctl.write_text("#!/usr/local/bin/python\nimport os,sys,subprocess\nfrom pathlib import Path\nif 'enable' in sys.argv:\n env=dict(os.environ);env.pop('PYTHONPATH',None)\n log=open(" + repr(str(service_log)) + ",'ab')\n p=subprocess.Popen([sys.executable," + repr(str(service)) + ",'--config'," + repr(str(installed / "config.json")) + "],env=env,stdout=log,stderr=log,start_new_session=True)\n Path(" + repr(str(root / "service.pid")) + ").write_text(str(p.pid))\n")
    os.chmod(systemctl, 0o700)
    # The disposable coordinator has its own network namespace; the real Docker
    # daemon still refuses conflicting published ports during container creation.
    ss = bin_dir / "ss"
    ss.write_text("#!/bin/sh\nprintf 'State Recv-Q Send-Q Local Address:Port Peer Address:Port\\n'\n")
    os.chmod(ss, 0o700)
    env = {**os.environ, "PATH": str(bin_dir) + ":" + os.environ["PATH"], "PYTHONPATH": str(shim),
        "NCT_CONTAINER": name, "NCT_RECOVERY_CONTAINER": console_name, "NCT_PERSIST_ROOT": str(persist),
        "NCT_RECOVERY_INSTALL_DIR": str(installed), "NCT_HTTPS_PORT": "18159", "NCT_RECOVERY_PORT": "18160"}
    env["NCT_RECOVERY_BIND_ADDRESS"] = "127.0.0.1"
    env["NCT_RECOVERY_STATE_DIR"] = str(root / "s")
    launcher = str(package / "scripts/nct-install-range.sh")
    with (root / "bootstrap.log").open("wb") as log:
        for mode in ("check", "all"):
            result = subprocess.run(["sh", launcher, gateway, mode], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
            if result.returncode:
                print((root / "bootstrap.log").read_text()[-18000:], flush=True)
                raise ValueError("Full package bootstrap failed")
    assert request("/health")["build_commit"] == release["commit"]
    handoff = request("/api/updates/launch", {})
    request("/api/exchange", {"code": handoff["url"].split("#handoff=")[1]}, console=True)
    operation = request("/api/status", console=True)["operation"]
    assert operation["phase"] == "awaiting_sign_in" and operation["backup_verified"] and operation["evidence_verified"]
    request("/api/verify-sign-in", {"username": "package-operator", "password": password}, console=True)
    assert request("/api/status", console=True)["operation"]["phase"] == "complete"
    current = engine.inspect(name)
    assert current["HostConfig"]["RestartPolicy"] == {"Name": "on-failure", "MaximumRetryCount": 3}
    assert "NCT_PACKAGE_PRESERVE_ME=retained-setting" in current["Config"]["Env"]
    assert any(m["Source"] == str(bootstrap) for m in current["Mounts"])
    assert engine.inspect(original_id)["HostConfig"]["RestartPolicy"]["Name"] == "no"
    assert not engine.inspect(original_id)["State"]["Running"]
    assert not (data / "recovery/update-maintenance.json").exists()
    assert all(m["Destination"] != "/var/run/docker.sock" for m in current["Mounts"])
    assert all(m["Destination"] not in {"/data", "/var/run/docker.sock"} for m in engine.inspect(console_name)["Mounts"])
    retained = json.loads(engine.command("exec", name, "python", "-c", "import json,sqlite3; d=sqlite3.connect('file:/data/analyzer.db?mode=ro',uri=True); print(json.dumps({'artifacts':d.execute('select count(*) from artifact_registry').fetchone()[0],'users':d.execute('select count(*) from analyst_users').fetchone()[0]}))"))
    assert retained["artifacts"] >= 1 and retained["users"] >= 1
    request("/api/close", {}, console=True)
    time.sleep(4)
    assert not engine.inspect(console_name)["State"]["Running"]
    engine.command("stop", name)
    engine.command("start", name)
    probe.wait_url(app_url + "/health/readiness", lambda value: value.get("healthy") is True)
    request("/api/auth/login", {"username": "package-operator", "password": password})
    receipt = {"result": "pass", "tested_manifest_sha256": tested, "commit": release["commit"], "build_id": release["build_id"],
        "source_build": "0.16.0-range-test-20261025-phase5-r1", "full_shell_bootstrap": True,
        "issuing_ca_https_verified": True, "retained_account_and_evidence": True,
        "environment_mount_port_and_restart_policy_preserved": True, "protected_empty_bootstrap_mount_preserved": True,
        "independent_console_handoff_and_sign_in": True, "console_stops_after_return": True,
        "stop_start_sign_in": True, "range_accepted": False, "real_systemd_boot_tested": False,
        "test_substitutions": ["administrative fixture peer exclusion", "systemctl launches exact copied service process", "ss replaced; Docker performs actual port admission"]}
    (root / "acceptance.json").write_text(json.dumps(receipt, indent=2))
    print("PASS: full package upgraded exact previous release with retained evidence/accounts/config, enabled independent console using issuing CA, verified sign-in/stop/start and closed console.", flush=True)
    engine.command("update", "--restart=no", name)
    engine.command("stop", name)
    if (root / "service.pid").exists():
        os.kill(int((root / "service.pid").read_text()), signal.SIGTERM)


if __name__ == "__main__":
    main()
