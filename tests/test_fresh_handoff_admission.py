import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import install_nct_recovery as installer


class Engine:
    def __init__(self, items):
        self.items = items

    def inspect(self, name):
        return copy.deepcopy(self.items[name])

    def command(self, *args):
        assert args[:2] == ("image", "inspect")
        return json.dumps([copy.deepcopy(self.items[args[2]])])


class Host:
    pass


def setup(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    with sqlite3.connect(data / "analyzer.db") as db:
        db.executescript("""
            CREATE TABLE analyst_users(username TEXT PRIMARY KEY, role TEXT, disabled INTEGER);
            CREATE TABLE analyst_auth_audit(audit_id INTEGER PRIMARY KEY, username TEXT, action TEXT, actor TEXT);
            CREATE TABLE analyst_sessions(token_hash TEXT PRIMARY KEY, username TEXT, created_at TEXT, expires_at TEXT);
            INSERT INTO analyst_users VALUES ('admin','admin',0);
            INSERT INTO analyst_auth_audit VALUES (1,'admin','create','bootstrap');
        """)
    cert, key, ca = (tmp_path / name for name in ("cert.pem", "key.pem", "ca.pem"))
    cert.write_text("certificate"); key.write_text("key"); ca.write_text("ca")
    manifest = tmp_path / "PACKAGE-MANIFEST.sha256"
    manifest.write_text("manifest")
    application_id = "sha256:" + "a" * 64
    console_id = "sha256:" + "b" * 64
    application_ref, console_ref = "nct:test", "nct-console:test"
    original = {
        "Id": "c" * 64, "Image": application_id, "Path": "uvicorn",
        "Args": ["app.main:app"],
        "Config": {"Image": application_ref, "Env": [
            "NCT_AUTH_MODE=local", "NCT_BUILD_ID=fresh-test",
            "NCT_BUILD_COMMIT=" + "d" * 40,
        ]},
        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}},
        "Mounts": [
            {"Destination": "/data", "Source": str(data), "Type": "bind", "RW": True},
            {"Destination": "/run/tls/nct-server.crt", "Source": str(cert), "Type": "bind", "RW": False},
        ],
    }
    release = {
        "contract": "nct-full-range-package-v1", "fresh_install": {"route": "test"},
        "build_id": "fresh-test", "commit": "d" * 40,
        "application_image": application_ref, "console_image": console_ref,
        "images": {
            application_ref: {"export_runtime_id": application_id},
            console_ref: {"export_runtime_id": console_id},
        },
    }
    release_file = tmp_path / "release.json"
    release_file.write_text(json.dumps(release))
    ownership = {
        "contract": "nct-fresh-bootstrap-resume:1", "phase": "runtime_ready",
        "admin_user": "admin", "data_dir": str(data),
        "cert_file": str(cert), "cert_sha256": installer._sha256_file(cert),
        "key_file": str(key), "key_sha256": installer._sha256_file(key),
        "release_sha256": installer._sha256_file(release_file),
        "package_manifest_sha256": installer._sha256_file(manifest),
        "final_runtime": installer._runtime_snapshot(original),
    }
    receipt = tmp_path / "deployment" / "bootstrap" / "fresh-resume.json"
    receipt.parent.mkdir(parents=True, mode=0o700)
    receipt.write_text(json.dumps(ownership))
    host = Host()
    host.data = data
    host.config = {
        "application_url": "https://nct.test:8445", "console_url": "https://nct.test:8446",
        "container": "nct", "console_container": "nct-recovery-console",
        "console_image_id": console_id, "ca_file": str(ca),
    }
    host.engine = Engine({
        application_ref: {"Id": application_id}, console_ref: {"Id": console_id},
    })
    return host, original, release_file, receipt, manifest, release


def test_owned_exact_fresh_runtime_is_admitted(tmp_path):
    host, original, release, receipt, manifest, _ = setup(tmp_path)
    proof = installer._fresh_release_proof(host, original, "admin", release, receipt, manifest)
    assert proof["contract"] == "nct-fresh-handoff-v1"
    assert proof["application_image_id"] == original["Image"]
    assert proof["bootstrap_receipt_sha256"] == installer._sha256_file(receipt)


def test_docker_mount_order_does_not_change_fresh_runtime_identity(tmp_path):
    host, original, release, receipt, manifest, _ = setup(tmp_path)
    original["Mounts"].reverse()
    proof = installer._fresh_release_proof(host, original, "admin", release, receipt, manifest)
    assert proof["contract"] == "nct-fresh-handoff-v1"


@pytest.mark.parametrize("change", ["pinned_image", "runtime", "mount_value", "receipt_mode", "receipt_phase", "tls", "manifest"])
def test_unowned_or_changed_fresh_runtime_is_rejected(tmp_path, change):
    host, original, release_file, receipt, manifest, release = setup(tmp_path)
    if change == "pinned_image":
        release["images"][release["application_image"]]["export_runtime_id"] = "sha256:" + "f" * 64
        release_file.write_text(json.dumps(release))
        value = json.loads(receipt.read_text())
        value["release_sha256"] = installer._sha256_file(release_file)
        receipt.write_text(json.dumps(value))
    elif change == "runtime":
        original["HostConfig"]["Privileged"] = True
    elif change == "mount_value":
        original["Mounts"][0]["RW"] = False
    elif change == "receipt_mode":
        receipt.chmod(0o666)
    elif change == "receipt_phase":
        value = json.loads(receipt.read_text()); value["phase"] = "password_committed"; receipt.write_text(json.dumps(value))
    elif change == "tls":
        Path(json.loads(receipt.read_text())["cert_file"]).write_text("changed")
    else:
        manifest.write_text("changed")
    with pytest.raises(ValueError):
        installer._fresh_release_proof(host, original, "admin", release_file, receipt, manifest)
