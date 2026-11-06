"""Real Docker/TLS acceptance for migrated-restore compatible recovery.

This is an explicit, disposable host exercise. It never scans a network and
only removes containers carrying its unique acceptance label.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import http.client
import json
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.parse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--v8-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--application-port", type=int, default=18195)
    args = parser.parse_args()
    root = args.root
    durable = (
        root.name == "_data"
        and root.parent.name.startswith("nct-retirement-recovery-")
        and root.parent.parent == Path("/var/lib/docker/volumes")
    )
    if not root.is_absolute() or not durable or any(root.iterdir()):
        raise ValueError("Use a new dedicated retirement-recovery acceptance volume")
    # The update host mounts its audited helper scripts into child containers.
    # Place the exact checkout scripts inside the dedicated Docker volume so the
    # daemon and this runner resolve the same durable path.
    shutil.copytree("/workspace/scripts", root / "tools" / "scripts")
    sys.path.insert(0, str(root / "tools" / "scripts"))
    import nct_update_host as module
    from build_nct_update import build

    own = Path("/etc/hostname").read_text().strip()

    class Engine(module.Docker):
        def command(self, *args, max_output_bytes=8 * 1024**2):
            result = subprocess.run(
                ["docker", *args], capture_output=True, text=True, timeout=180,
            )
            if result.returncode:
                detail = (result.stderr or result.stdout).strip()
                (root / "docker-error.log").write_text(
                    f"{args[0]} {args[1] if len(args) > 1 else ''}: {detail}\n",
                    encoding="utf-8",
                )
                raise ValueError("Docker refused the acceptance operation: " + detail)
            if len(result.stdout.encode()) + len(result.stderr.encode()) > max_output_bytes:
                raise ValueError("Docker acceptance output exceeds its limit")
            return result.stdout

        def api(self, method, path, body=None, *, timeout=60):
            connection = http.client.HTTPConnection("localhost", timeout=timeout)
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.sock.settimeout(timeout)
            connection.sock.connect("/var/run/docker.sock")
            try:
                connection.request(
                    method, path, None if body is None else module.canonical(body),
                    {"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                raw = response.read(1024**2)
                result = json.loads(raw)
                if response.status not in {200, 201}:
                    detail = str(result.get("message", result))[:1000]
                    (root / "docker-error.log").write_text(
                        f"{method} {path}: {detail}\n", encoding="utf-8",
                    )
                    raise ValueError("Docker refused the acceptance operation: " + detail)
                return result
            finally:
                connection.close()

        def inventory(self):
            return [
                item for item in super().inventory()
                if not item["Id"].startswith(own)
            ]

    engine = Engine()
    old_image = json.loads(engine.command("image", "inspect", args.v8_image))[0]
    candidate_image = json.loads(
        engine.command("image", "inspect", args.candidate_image)
    )[0]
    old_env = dict(
        item.split("=", 1)
        for item in old_image["Config"].get("Env", []) if "=" in item
    )
    new_env = dict(
        item.split("=", 1)
        for item in candidate_image["Config"].get("Env", []) if "=" in item
    )
    old_build = {
        "build_id": old_env["NCT_BUILD_ID"],
        "build_commit": old_env["NCT_BUILD_COMMIT"],
    }
    if old_build["build_id"] == new_env["NCT_BUILD_ID"]:
        raise ValueError("Acceptance requires distinct version-8 and candidate builds")

    fixture = root.parent.name
    name = "nct-retirement-recovery-" + secrets.token_hex(5)
    data, state, guard, tls = (root / item for item in ("data", "state", "guard", "tls"))
    for path in (data, state, guard, tls):
        path.mkdir(mode=0o700)
    cert, key = tls / "server.crt", tls / "server.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-subj", "/CN=host.docker.internal", "-addext",
            "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True, capture_output=True,
    )
    password = secrets.token_urlsafe(24)
    application_url = f"https://host.docker.internal:{args.application_port}"
    config = {
        "state_dir": str(state), "data_dir": str(data),
        "retirement_guard_dir": str(guard), "container": name,
        "console_container": name + "-console",
        "console_image_id": candidate_image["Id"],
        "application_url": application_url,
        "console_url": "https://host.docker.internal:1",
        "ca_file": str(cert), "allowed_operators": "all",
        "maintenance_lock": str(root / "maintenance.lock"),
    }
    context = ssl.create_default_context(cafile=str(cert))

    def opener():
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}),
        )

    def request(browser, path, body=None):
        raw = None if body is None else json.dumps(body).encode()
        with browser.open(
            urllib.request.Request(
                application_url + path, data=raw,
                headers={"Content-Type": "application/json"},
            ),
            timeout=120,
        ) as response:
            return json.load(response)

    def sign_in(browser):
        result = request(
            browser, "/api/auth/login",
            {"username": "fixture-admin", "password": password},
        )
        assert result.get("authenticated") is True

    def import_xml(browser, filename, payload):
        boundary = "nct-compatible-recovery-boundary"
        body = (
            b"--" + boundary.encode()
            + b'\r\nContent-Disposition: form-data; name="file"; filename="'
            + filename.encode() + b'"\r\nContent-Type: application/xml\r\n\r\n'
            + payload + b"\r\n--" + boundary.encode() + b"--\r\n"
        )
        with browser.open(
            urllib.request.Request(
                application_url + "/api/import", data=body,
                headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
            ),
            timeout=60,
        ) as response:
            return json.load(response)

    class InjectedFailureHost(module.Host):
        injected = False
        retired_encounter = None

        def verify_health(self, operation, original=False):
            result = super().verify_health(operation, original=original)
            if not original and not self.injected:
                self.injected = True
                browser = opener()
                sign_in(browser)
                preview = request(
                    browser, "/api/evidence-retirements/preview",
                    {
                        "source_family": "nmap_import",
                        "encounter_id": self.retired_encounter,
                    },
                )
                confirmation = (
                    f"RETIRE nmap_import {self.retired_encounter} AT "
                    f"{preview['authority_revision']} "
                    f"{preview['identity_snapshot_sha256'][:12]}"
                )
                retired = request(
                    browser, "/api/evidence-retirements",
                    {
                        "source_family": "nmap_import",
                        "encounter_id": self.retired_encounter,
                        "reason": "real Docker migrated-restore acceptance",
                        "review_token": preview["review_token"],
                        "confirmation": confirmation,
                    },
                )
                assert retired["status"] == "retired" and retired["revision"] == 1
                (data / "candidate-later-evidence.txt").write_text(
                    "candidate later bytes", encoding="utf-8",
                )
                raise ValueError("injected failure after protected retirement")
            return result

    label = "org.nct.retirement-recovery=" + fixture
    try:
        engine.command(
            "run", "-d", "--name", name, "--label", label,
            "--restart", "on-failure:3",
            "-p", f"127.0.0.1:{args.application_port}:8080",
            "-v", f"{data}:/data",
            "-v", f"{cert}:/run/tls/server.crt:ro",
            "-v", f"{key}:/run/tls/server.key:ro",
            "-e", "NCT_AUTH_MODE=local", "-e", "NCT_COOKIE_SECURE=1",
            "-e", "NCT_BOOTSTRAP_ADMIN=fixture-admin",
            "-e", "NCT_BOOTSTRAP_PASSWORD=" + password,
            old_image["Id"], "uvicorn", "app.main:app", "--host", "0.0.0.0",
            "--port", "8080", "--ssl-certfile", "/run/tls/server.crt",
            "--ssl-keyfile", "/run/tls/server.key",
        )
        host = InjectedFailureHost(config, engine)
        host.wait_url(
            application_url + "/health/readiness",
            lambda value: value.get("healthy") is True,
        )
        browser = opener()
        sign_in(browser)
        xml = (
            b'<?xml version="1.0"?><nmaprun scanner="nmap" start="1780000000">'
            b'<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
            b'<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
            b'<ports><port protocol="tcp" portid="443"><state state="open"/>'
            b'<service name="https"/></port></ports></host><runstats>'
            b'<finished time="1780000001" exit="success"/>'
            b'<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        )
        first = import_xml(browser, "retire-this.xml", xml)
        second = import_xml(browser, "keep-this.xml", xml)
        InjectedFailureHost.retired_encounter = first["artifact_observation_id"]
        assert second["artifact_observation_id"] != first["artifact_observation_id"]
        original_files = {
            str(path.relative_to(data)): module.digest_file(path)
            for path in data.rglob("*") if path.is_file()
        }
        package = root / "candidate-update.tar.gz"
        build(args.candidate_image, [old_build], package)
        with package.open("rb") as stream:
            plan = host.stage(stream, package.stat().st_size, "fixture-admin")
        host.apply(plan["plan_digest"], "fixture-admin")
        operation = host.read()
        assert operation["phase"] == "awaiting_compatible_recovery", host.public()
        assert operation["retirement"]["revision"] == 1
        assert Path(operation["quarantine_path"]).joinpath(
            "candidate-later-evidence.txt"
        ).read_text() == "candidate later bytes"

        host.resume_compatible_recovery("fixture-admin")
        assert host.read()["phase"] == "awaiting_restore_sign_in"
        result = host.confirm("fixture-admin", password, "fixture-admin")
        assert result["operation"]["phase"] == "restored"
        assert host.read()["controller_sign_in_verified"] is True
        runtime = engine.inspect(name)
        assert runtime["Image"] == host.read()["candidate_image_id"]
        assert runtime["State"]["Running"] is True
        assert runtime["HostConfig"]["RestartPolicy"] == {
            "Name": "on-failure", "MaximumRetryCount": 3,
        }
        health = request(opener(), "/health")
        assert health["build_id"] == new_env["NCT_BUILD_ID"]
        with __import__("sqlite3").connect(data / "analyzer.db") as db:
            active = {
                row[0] for row in db.execute(
                    "SELECT observation_id FROM artifact_observations "
                    "WHERE observation_id NOT IN "
                    "(SELECT encounter_id FROM evidence_retirement_events)"
                )
            }
            account = db.execute(
                "SELECT username,role,disabled FROM analyst_users "
                "WHERE username='fixture-admin'"
            ).fetchone()
        assert first["artifact_observation_id"] not in active
        assert second["artifact_observation_id"] in active
        assert account == ("fixture-admin", "admin", 0)
        assert all(
            (data / relative).is_file()
            for relative in original_files
            if relative.startswith("artifacts/")
        )
        assert not (data / "candidate-later-evidence.txt").exists()
        module.save(root / "acceptance.json", {
            "result": "pass", "old_build": old_build,
            "candidate_build": {
                "build_id": new_env["NCT_BUILD_ID"],
                "build_commit": new_env["NCT_BUILD_COMMIT"],
            },
            "tls_verified": True, "account_verified": True,
            "retirement_revision": operation["retirement"]["revision"],
            "retired_encounter": first["artifact_observation_id"],
            "active_matching_encounter": second["artifact_observation_id"],
        })
        print(
            "PASS: real v8 backup restore, protected retirement, exact compatible "
            "runtime, TLS sign-in, final restart and retained evidence verified.",
            flush=True,
        )
    finally:
        for identity in engine.command(
            "ps", "-aq", "--filter", "label=" + label,
        ).split():
            try:
                engine.command("update", "--restart=no", identity)
                engine.command("rm", "-f", identity)
            except ValueError:
                pass


if __name__ == "__main__":
    main()
