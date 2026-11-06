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
import tarfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--source-image", default="network-characterization-tool:0.16.0-range-test-20261025-phase5-r1")
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
    source_env = dict(value.split("=", 1) for value in json.loads(engine.command("image", "inspect", args.source_image))[0]["Config"]["Env"] if "=" in value)
    source = next(s for s in release["supported_sources"] if s["build_id"] == source_env["NCT_BUILD_ID"] and s["commit"] == source_env["NCT_BUILD_COMMIT"])
    source_version = source["schema_version"]
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
    launch = ["run", "-d", "--name", name, "--restart", "on-failure:3", "--cap-add", "NET_RAW",
        "-p", "127.0.0.1:18159:8445", "-v", f"{data}:/data", "-v", f"{tls}/tls/nct-server.crt:/run/tls/nct-server.crt:ro",
        "-v", f"{tls}/tls/nct-server.key:/run/tls/nct-server.key:ro", "-v", f"{bootstrap}:/run/retained-bootstrap:ro",
        "-e", "NCT_AUTH_MODE=local", "-e", "NCT_COOKIE_SECURE=1", "-e", "NCT_BOOTSTRAP_ADMIN=package-operator",
        "-e", "NCT_BOOTSTRAP_PASSWORD_FILE=/run/retained-bootstrap", "-e", "NCT_PACKAGE_PRESERVE_ME=retained-setting",
        args.source_image, "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8445",
        "--ssl-certfile", "/run/tls/nct-server.crt", "--ssl-keyfile", "/run/tls/nct-server.key"]
    initial = list(launch)
    if source_version == 8:
        initial[initial.index(args.source_image)] = "network-characterization-tool:0.16.0-range-test-20261025-phase5-r1"
    original_id = engine.command(*initial)
    original_image_id = engine.inspect(original_id)["Image"]
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
    if source_version == 8:
        engine.command("update", "--restart=no", original_id)
        engine.command("stop", original_id)
        engine.command("rename", original_id, name + "-schema7-seed")
        original_id = engine.command(*launch)
        probe.wait_url(app_url + "/health/readiness", lambda value: value.get("healthy") is True)
        request("/api/auth/login", {"username": "package-operator", "password": password})
        assert request("/health")["build_commit"] == source["commit"]
        ledger = json.loads(engine.command("exec", name, "python", "-c", "import json,sqlite3;d=sqlite3.connect('/data/analyzer.db');print(json.dumps(d.execute('select target_schema_version, originating_build_commit from nct_schema_migrations order by target_schema_version').fetchall()))"))
        assert len(ledger) == 8 and ledger[0][1] == "be92fb78e938adc3fced581629d4609ac0a43f6a" and ledger[-1][1] == source["commit"]
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
    systemctl.write_text("#!/usr/local/bin/python\nimport os,sys,subprocess\nfrom pathlib import Path\nif 'show' in sys.argv: print('not-found')\nif 'enable' in sys.argv:\n env=dict(os.environ);env.pop('PYTHONPATH',None)\n log=open(" + repr(str(service_log)) + ",'ab')\n p=subprocess.Popen([sys.executable," + repr(str(service)) + ",'--config'," + repr(str(installed / "config.json")) + "],env=env,stdout=log,stderr=log,start_new_session=True)\n Path(" + repr(str(root / "service.pid")) + ").write_text(str(p.pid))\n")
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
    assert request("/health")["build_commit"] == source["commit"]
    preserved = engine.inspect(name)
    assert preserved["Image"] == original_image_id
    assert any(m["Source"] == str(data) and m["Destination"] == "/data" for m in preserved["Mounts"])
    with browser.open(app_url + imported["download_url"], timeout=30) as response:
        assert response.read() == xml
    handoff = request("/api/updates/launch", {})
    request("/api/exchange", {"code": handoff["url"].split("#handoff=")[1]}, console=True)
    update = package / release["gui_update"]["file"]
    with update.open("rb") as stream:
        with browser.open(urllib.request.Request(
            console_url + "/api/upload", data=stream,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(update.stat().st_size), "X-NCT-Recovery": "1"},
        ), timeout=180) as response:
            plan = json.load(response)
    request("/api/apply", {"plan_digest": plan["plan_digest"]}, console=True)
    for _ in range(180):
        operation = request("/api/status", console=True)["operation"]
        if operation["phase"] == "awaiting_sign_in":
            break
        if operation["phase"] in {"failed", "interrupted", "awaiting_restore_sign_in"}:
            raise AssertionError(operation)
        time.sleep(1)
    else:
        raise AssertionError(operation)
    assert operation["backup_verified"] and operation["evidence_verified"]
    request("/api/verify-sign-in", {"username": "package-operator", "password": password}, console=True)
    assert request("/api/status", console=True)["operation"]["phase"] == "complete"
    assert request("/health")["build_commit"] == release["commit"]
    current = engine.inspect(name)
    assert current["Image"] == json.loads(engine.command("image", "inspect", release["application_image"]))[0]["Id"]
    assert engine.inspect(console_name)["Image"] == json.loads(engine.command("image", "inspect", release["console_image"]))[0]["Id"]
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
    rollback_handoff = request("/api/updates/launch", {})
    request("/api/exchange", {"code": rollback_handoff["url"].split("#handoff=")[1]}, console=True)
    later = data / "later-evidence.txt"
    later.write_bytes(b"preserve after protected restore")
    request("/api/rollback", {"confirm": "RESTORE"}, console=True)
    compatible_restore = False
    for _ in range(180):
        restore_operation = request("/api/status", console=True)["operation"]
        if restore_operation["phase"] == "awaiting_compatible_recovery":
            compatible_restore = True
            request("/api/resume-compatible", {"confirm": "START COMPATIBLE RECOVERY"}, console=True)
        elif restore_operation["phase"] == "awaiting_restore_sign_in":
            break
        if restore_operation["phase"] in {"failed", "interrupted"}:
            raise AssertionError(restore_operation)
        time.sleep(1)
    else:
        raise AssertionError(restore_operation)
    request("/api/verify-sign-in", {"username": "package-operator", "password": password}, console=True)
    restored_operation = request("/api/status", console=True)["operation"]
    assert restored_operation["phase"] == "restored"
    assert request("/health")["build_commit"] == (release["commit"] if compatible_restore else source["commit"])
    quarantine = Path(restored_operation["quarantine_path"])
    assert (quarantine / "later-evidence.txt").read_bytes() == b"preserve after protected restore"
    with browser.open(app_url + imported["download_url"], timeout=30) as response:
        assert response.read() == xml
    restored_runtime = engine.inspect(name)
    if compatible_restore:
        assert restored_runtime["Image"] == json.loads(engine.command("image", "inspect", release["application_image"]))[0]["Id"]
        assert "NCT_RETIREMENT_GUARD_MODE=required" in restored_runtime["Config"]["Env"]
        assert any(m["Destination"] == "/run/nct-retirement-guard" for m in restored_runtime["Mounts"])
        assert restored_operation["compatible_recovery"]["build_commit"] == release["commit"]
    request("/api/close", {}, console=True)
    time.sleep(4)
    assert not engine.inspect(console_name)["State"]["Running"]
    engine.command("stop", name)
    old_check = root / "old-image-copy"
    old_check.mkdir()
    shutil.copyfile(data / "analyzer.db", old_check / "analyzer.db")
    refusal = engine.command("run", "--rm", "--network", "none", "-v", f"{old_check}:/data",
        "network-characterization-tool:0.16.0-range-test-20261025-phase5-r1", "python", "-c",
        "from pathlib import Path; from app.schema_compatibility import begin_schema_migration,SchemaCompatibilityError;\ntry: begin_schema_migration(Path('/data/analyzer.db'))\nexcept SchemaCompatibilityError as e:\n assert 'newer than' in str(e); print('OLD_IMAGE_REFUSED_SCHEMA8')\nelse: raise RuntimeError('Old image opened version8')")
    assert "OLD_IMAGE_REFUSED_SCHEMA8" in refusal
    engine.command("start", name)
    probe.wait_url(app_url + "/health/readiness", lambda value: value.get("healthy") is True)
    request("/api/auth/login", {"username": "package-operator", "password": password})
    def isolated_ready(candidate):
        for _ in range(60):
            try:
                value = json.loads(engine.command("exec", candidate, "python", "-c", "import json,urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/health/readiness').read().decode())"))
                if value.get("healthy") is True:
                    return
            except ValueError:
                pass
            time.sleep(1)
        raise ValueError("Isolated release failed readiness")
    restored = root / "restored-original"
    restored.mkdir()
    restored_data = restored / "data"
    restored_data.mkdir()
    archive_path = Path(restored_operation["backup_path"])
    with tarfile.open(archive_path) as archive:
        archive.extractall(restored_data, filter="data")
    restored_name = name + "-restored"
    engine.command("run", "-d", "--name", restored_name, "--network", "none", "-e", "NCT_AUTH_MODE=local", "-v", f"{restored / 'data'}:/data",
        args.source_image)
    isolated_ready(restored_name)
    engine.command("exec", restored_name, "python", "-c", "import sqlite3; d=sqlite3.connect('/data/analyzer.db'); assert d.execute('select schema_version from nct_schema_state').fetchone()[0]==" + str(source_version) + "; assert d.execute('select count(*) from artifact_registry').fetchone()[0]>=1; assert d.execute('select count(*) from analyst_users').fetchone()[0]>=1")
    engine.command("stop", restored_name)
    receipt = {"result": "pass", "tested_manifest_sha256": tested, "commit": release["commit"], "build_id": release["build_id"],
        "source_build": source["build_id"], "source_commit": source["commit"], "source_schema_version": source_version,
        "source_migrated_from_schema7": source_version == 8,
        "images": release["images"], "full_shell_bootstrap": True,
        "existing_install_upgrade": release["existing_install_upgrade"],
        "source_identity_preserved_during_recovery_setup": True,
        "source_evidence_preserved_during_recovery_setup": True,
        "issuing_ca_https_verified": True, "retained_account_and_evidence": True,
        "environment_mount_port_and_restart_policy_preserved": True, "protected_empty_bootstrap_mount_preserved": True,
        "independent_console_handoff_and_sign_in": True, "protected_restore_verified": True,
        "compatible_recovery_verified": compatible_restore,
        "compatible_recovery_result": "used" if compatible_restore else "not-needed",
        "console_stops_after_return": True,
        "stop_start_sign_in": True, "range_accepted": False, "real_systemd_boot_tested": False,
        "schema_version": 9, "old_image_refuses_schema9": True, "original_backup_booted": True,
        "original_backup_schema_version": source_version,
        "test_substitutions": ["administrative fixture peer exclusion", "systemctl launches exact copied service process", "ss replaced; Docker performs actual port admission"]}
    (root / "acceptance.json").write_text(json.dumps(receipt, indent=2))
    print("PASS: full package upgraded exact previous release with retained evidence/accounts/config, enabled independent console using issuing CA, verified sign-in/stop/start and closed console.", flush=True)
    engine.command("update", "--restart=no", name)
    engine.command("stop", name)
    if (root / "service.pid").exists():
        os.kill(int((root / "service.pid").read_text()), signal.SIGTERM)


if __name__ == "__main__":
    main()
