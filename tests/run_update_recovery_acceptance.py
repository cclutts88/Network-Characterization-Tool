"""Explicit Docker acceptance; disposable data and operation-prefixed containers only.

Run in tests/docker/update-host-acceptance.Dockerfile with the Docker socket and
the same /tmp/nct-update-acceptance-* bind path on host and runner. No real scans.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--application-port", type=int, default=18151)
    parser.add_argument("--console-port", type=int, default=18152)
    parser.add_argument("--keep-preview", action="store_true")
    parser.add_argument("--resume-preview", action="store_true")
    args = parser.parse_args()
    root = args.root
    durable = root.name == "_data" and root.parent.name.startswith("nct-update-acceptance-") and root.parent.parent == Path("/var/lib/docker/volumes")
    if not root.is_absolute() or not (durable or root.name.startswith("nct-update-acceptance-") and root.parent == Path("/tmp")):
        raise ValueError("Acceptance requires its dedicated test storage root")
    fixture_id = root.parent.name if durable else root.name
    root.mkdir(exist_ok=True, mode=0o700)
    tools = root / "tools"
    tools.mkdir(exist_ok=True)
    for name in ("nct_update_host.py", "nct-range-data-check.py", "build_nct_update.py", "nct_update_work.py"):
        shutil.copyfile(Path("/workspace/scripts") / name, tools / name)
    sys.path.insert(0, str(tools))
    import nct_update_host as module
    from build_nct_update import build
    # This container represents the privileged host service. Exclude only its
    # exact immutable identity from peer-application inspection; production runs
    # on the host and has no such container. All actual NCT peers remain checked.
    class HostHarnessDocker(module.Docker):
        def inventory(self):
            own_prefix = Path("/etc/hostname").read_text().strip()
            return [item for item in super().inventory() if not item['Id'].startswith(own_prefix)]
        def command(self, *args):
            result = super().command(*args)
            if args[:2] == ("ps", "-aq"):
                own_prefix = Path("/etc/hostname").read_text().strip()
                return "\n".join(value for value in result.split() if not value.startswith(own_prefix))
            return result
    engine = HostHarnessDocker()
    class PreviewHandler(module.Handler):
        def handle_request(self):
            value = super().handle_request()
            if isinstance(value, dict):
                for key in ("url", "application_url"):
                    if isinstance(value.get(key), str):
                        # Desktop fixture's host-probe DNS differs from its
                        # browser's loopback URL; real deployments use one origin.
                        value[key] = value[key].replace("http://host.docker.internal:", "http://127.0.0.1:")
            return value
    if args.resume_preview:
        import stat
        config = json.loads((root / "acceptance-config.json").read_text())
        host = module.Host(config, engine, reconcile=True)
        for key, launch_only in (("launch_socket", True), ("control_socket", False)):
            path = Path(config[key])
            if path.exists():
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise ValueError("Preview socket path is not a socket")
                path.unlink()
            server = module.Server(str(path), PreviewHandler)
            server.host, server.launch_only = host, launch_only
            threading.Thread(target=server.serve_forever, daemon=True).start()
        access = json.loads((root / "preview-access.json").read_text())
        access["console_code"] = host.token("preview-operator")
        module.save(root / "preview-access.json", access)
        print("Persistent preview helper resumed; no update or repair was started.", flush=True)
        while True:
            time.sleep(30)
    name = "nct-update-test-" + secrets.token_hex(6)
    data, state = root / "data", root / "state"
    data.mkdir(mode=0o700)
    launch, control, spool = root / "launch", root / "control", root / "spool"
    for path in (launch, control, spool):
        path.mkdir(mode=0o700)
    password = secrets.token_urlsafe(18)
    old_image = json.loads(engine.command("image", "inspect", "nct-update-acceptance:old"))[0]["Id"]
    config = {"state_dir": str(state), "data_dir": str(data), "container": name,
        "console_container": name + "-console", "console_image_id": old_image,
        "application_url": f"http://host.docker.internal:{args.application_port}",
        "console_url": f"http://host.docker.internal:{args.console_port}",
        "launch_socket": str(launch / "launch.sock"), "control_socket": str(control / "control.sock"),
        "maintenance_lock": str(root / "maintenance.lock")}
    module.save(root / "acceptance-config.json", config)
    engine.command("run", "-d", "--name", name, "--label", "org.nct.acceptance=" + fixture_id,
        "--restart", "on-failure:3", "-p", f"127.0.0.1:{args.application_port}:8080",
        "-v", f"{data}:/data", "-v", f"{launch}:/run/nct-update:ro",
        "-e", "NCT_AUTH_MODE=local", "-e", "NCT_COOKIE_SECURE=0",
        "-e", "NCT_BOOTSTRAP_ADMIN=preview-operator", "-e", "NCT_BOOTSTRAP_PASSWORD=" + password,
        old_image)
    host = module.Host(config, engine)
    servers = []
    for path, launch_only in ((config["launch_socket"], True), (config["control_socket"], False)):
        server = module.Server(path, PreviewHandler)
        server.host, server.launch_only = host, launch_only
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    engine.command("create", "--name", config["console_container"], "--label", "org.nct.acceptance=" + fixture_id,
        "-p", f"127.0.0.1:{args.console_port}:8446", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "-v", f"{control}:/run/nct-recovery:ro", "-v", f"{spool}:/staging",
        "-e", "NCT_RECOVERY_INSECURE_TEST=1", "-e", "NCT_RECOVERY_SPOOL=/staging", old_image,
        "uvicorn", "app.recovery_console:app", "--host", "0.0.0.0", "--port", "8446")
    host.wait_url(config["application_url"] + "/health/readiness", lambda value: value.get("healthy") is True)
    cookies = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies), urllib.request.ProxyHandler({}))
    def request(path, body=None, base=None):
        headers = {"Content-Type": "application/json", "X-NCT-Recovery": "1"}
        raw = None if body is None else json.dumps(body).encode()
        with browser.open(urllib.request.Request((base or config["application_url"]) + path, data=raw, headers=headers), timeout=120) as response:
            return json.load(response)
    request("/api/auth/login", {"username": "preview-operator", "password": password})
    # Import an original file through the public application intake, then verify
    # that the real canonical artifact survives both replacement and rollback.
    xml = b'<?xml version="1.0"?><nmaprun scanner="nmap" start="1780000000"><scaninfo type="syn" protocol="tcp" numservices="1" services="443"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><runstats><finished time="1780000001" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    boundary = "nct-acceptance-boundary"
    body = b'--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="file"; filename="acceptance.xml"\r\nContent-Type: application/xml\r\n\r\n' + xml + b'\r\n--' + boundary.encode() + b'--\r\n'
    with browser.open(urllib.request.Request(config["application_url"] + "/api/import", data=body,
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary}), timeout=30) as response:
        imported = json.load(response)
    print("Original file imported through NCT.", flush=True)
    release = build("nct-update-acceptance:new", [{"build_id": "nct-update-acceptance-old", "build_commit": "a" * 40}], root / "update.tar.gz")
    print("Single-file update package built.", flush=True)
    handoff = request("/api/updates/launch", {})
    code = handoff["url"].split("#handoff=", 1)[1]
    request("/api/exchange", {"code": code}, config["console_url"])
    with (root / "update.tar.gz").open("rb") as stream:
        upload = urllib.request.Request(config["console_url"] + "/api/upload", data=stream, method="POST", headers={
            "Content-Type": "application/octet-stream", "Content-Length": str((root / "update.tar.gz").stat().st_size), "X-NCT-Recovery": "1"})
        with browser.open(upload, timeout=180) as response:
            validated = json.load(response)
    assert validated["phase"] == "validated"
    print("Package validated against the running source and disposable schema copy.", flush=True)
    def wait_phase(expected, allow_recovery=False):
        for _ in range(180):
            phase = host.read()["phase"]
            if phase == expected:
                return
            if phase in {"interrupted", "failed"} and not allow_recovery:
                raise AssertionError(host.public())
            time.sleep(1)
        raise AssertionError(host.public())
    request("/api/apply", {"plan_digest": validated["plan_digest"]}, config["console_url"])
    wait_phase("awaiting_sign_in")
    print("Replacement result: " + json.dumps(host.public()), flush=True)
    assert host.read()["phase"] == "awaiting_sign_in", host.public()
    queued = request("/__acceptance/queue-local", {})
    assert queued["local_attempts"] == ["queued"]
    assert queued["update_pause_present"] and not queued["passive_worker_alive"]
    request("/api/verify-sign-in", {"username": "preview-operator", "password": password}, config["console_url"])
    assert host.read()["phase"] == "complete"
    assert engine.inspect(name)["HostConfig"]["RestartPolicy"] == {"Name": "on-failure", "MaximumRetryCount": 3}
    assert request("/health")["build_id"] == "nct-update-acceptance-new"
    for _ in range(60):
        workers = request("/__acceptance/workers")
        if workers["local_attempts"] == ["completed"]:
            break
        time.sleep(1)
    assert workers["local_attempts"] == ["completed"], workers
    assert workers["passive_worker_alive"] and workers["storage_enabled"] and not workers["update_pause_present"], workers
    print("Real queued local analysis completed after release; passive worker and storage processing are active.", flush=True)
    print("Exact new build, real sign-in, readiness and retained evidence passed.", flush=True)
    request("/api/rollback", {"confirm": "RESTORE"}, config["console_url"])
    wait_phase("awaiting_restore_sign_in")
    assert host.read()["phase"] == "awaiting_restore_sign_in", host.public()
    assert host.read()["controller_sign_in_verified"] is False
    request("/api/verify-sign-in", {"username": "preview-operator", "password": password}, config["console_url"])
    assert host.read()["phase"] == "restored", host.public()
    assert request("/health")["build_id"] == "nct-update-acceptance-old"
    assert Path(host.read()["quarantine_path"]).is_dir()
    print("Verified original restored; post-update data preserved.", flush=True)
    build("nct-update-acceptance:failed", [{"build_id": "nct-update-acceptance-old", "build_commit": "a" * 40}], root / "failed-update.tar.gz")
    with (root / "failed-update.tar.gz").open("rb") as stream:
        upload = urllib.request.Request(config["console_url"] + "/api/upload", data=stream, method="POST", headers={
            "Content-Type": "application/octet-stream", "Content-Length": str((root / "failed-update.tar.gz").stat().st_size), "X-NCT-Recovery": "1"})
        with browser.open(upload, timeout=180) as response:
            failed_plan = json.load(response)
    request("/api/apply", {"plan_digest": failed_plan["plan_digest"]}, config["console_url"])
    wait_phase("awaiting_restore_sign_in", allow_recovery=True)
    # Status remains available through the independent console even though the
    # failed release cannot serve the application. Completion needs fresh sign-in.
    assert request("/api/status", base=config["console_url"])["operation"]["controller_sign_in_verified"] is False
    request("/api/verify-sign-in", {"username": "preview-operator", "password": password}, config["console_url"])
    assert request("/health")["build_id"] == "nct-update-acceptance-old"
    assert Path(host.read()["quarantine_path"]).is_dir()
    print("Real failed release automatically restored the cold backup; console and fresh sign-in remained usable.", flush=True)
    host.prepare_repair("preview-operator")
    assert host.read()["phase"] == "repair_review"
    assert host.read()["repair_summary"]["affected_count"] == 0
    host.cancel_repair("preview-operator")
    print("Clean unfinished-work preview and cancellation passed.", flush=True)
    host.stop_exact(engine.inspect(name))
    seed = '''import json, sqlite3
db=sqlite3.connect('/data/analyzer.db')
for run_id,status in [('console-queued-1','queued'),('console-started-2','running')]:
 m={'run_id':run_id,'created_at':'2026-10-27T00:00:00Z','status':status,'operator':'preview-operator','targets':['192.0.2.0/29'],'profile':'Common ports','scheduled':False}
 if status=='running': m.update(started_at='2026-10-27T00:01:00Z',execution_claim={'owner':'retired-test-worker'})
 db.execute('INSERT INTO scan_runs(run_id,created_at,status,operator_name,reason,originating_host,interface_name,profile,manifest_json) VALUES(?,?,?,?,?,?,?,?,?)',(run_id,m['created_at'],status,'preview-operator','isolated test','fixture','eth0','Common ports',json.dumps(m)))
db.commit();db.close()
'''
    host.run_helper(old_image, ["--mount", f"type=bind,src={data},dst=/data"], ["-c", seed])
    host.prepare_repair("preview-operator")
    assert host.read()["repair_summary"]["safe_to_apply"] is True, host.public()
    assert host.read()["repair_summary"]["preserved_scan_queue"] == 1
    digest = host.read()["plan_digest"]
    try:
        host.apply_repair("stale-plan", "preview-operator")
        raise AssertionError("Changed plan was accepted")
    except ValueError:
        pass
    host.apply_repair(digest, "preview-operator")
    assert host.read()["phase"] == "awaiting_repair_sign_in", host.public()
    host.confirm("preview-operator", password, "preview-operator")
    observed = json.loads(engine.command("exec", name, "python", "-c",
        "import json,sqlite3; from pathlib import Path; from app.scan_work_recovery import scan_contact_paused,device_contact_paused; d=sqlite3.connect('file:/data/analyzer.db?mode=ro',uri=True); print(json.dumps({'runs':dict(d.execute(\"SELECT run_id,status FROM scan_runs WHERE run_id LIKE 'console-%'\")), 'scan_paused':scan_contact_paused(Path('/data')),'device_paused':device_contact_paused(Path('/data'))}))"))
    assert observed["runs"]["console-queued-1"] == "queued"
    assert observed["runs"]["console-started-2"] == "interrupted"
    assert observed["scan_paused"] and observed["device_paused"]
    print("Real work repair preserved the waiting scan, interrupted the retired worker and kept contact paused.", flush=True)
    module.save(root / "acceptance-result.json", {"result": "pass", "operation": host.public(), "original_import": imported})
    if args.keep_preview:
        module.save(root / "preview-access.json", {"username": "preview-operator", "password": password, "console_code": host.token("preview-operator")})
        print("Preview remains available on the configured test ports; access is in the private acceptance folder.", flush=True)
        while True:
            time.sleep(30)
    else:
        for server in servers:
            server.shutdown()
        # Keep evidence and receipts. Remove only exact acceptance-owned containers.
        for item in engine.command("ps", "-aq", "--filter", "label=org.nct.acceptance=" + fixture_id).split():
            engine.command("rm", "-f", item)


if __name__ == "__main__":
    main()
