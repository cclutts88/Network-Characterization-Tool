import importlib.util
import json
from pathlib import Path
import sys
import os
import shutil
import subprocess
import tarfile
import zipfile

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"
spec = importlib.util.spec_from_file_location("range_package", SCRIPTS / "build_nct_range_package.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def staged(tmp_path):
    root = tmp_path / "stage"
    root.mkdir()
    (root / "release.json").write_text(json.dumps({"commit": "a" * 40}))
    (root / "image.tar").write_bytes(b"exact image archive")
    package.write_manifest(root)
    return root


def test_seal_binds_tested_files_and_includes_checksums_in_one_transfer(tmp_path):
    root = staged(tmp_path)
    receipt = tmp_path / "acceptance.json"
    receipt.write_text(json.dumps({"result": "pass", "commit": "a" * 40, "tested_manifest_sha256": package.verify_manifest(root)}))
    output = tmp_path / "release.zip"
    result = package.seal(root, receipt, output)
    assert result["sha256"] == package.digest(output)
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert "NCT-Air-Gapped-Range-Deployment/PACKAGE-MANIFEST.sha256" in archive.namelist()
        assert "NCT-Air-Gapped-Range-Deployment/VALIDATION.json" in archive.namelist()
    package.verify_manifest(root)


@pytest.mark.parametrize("change", ["tamper", "extra", "wrong_commit", "wrong_manifest", "failed"])
def test_seal_rejects_changed_or_unaccepted_payload(tmp_path, change):
    root = staged(tmp_path)
    evidence = {"result": "pass", "commit": "a" * 40, "tested_manifest_sha256": package.verify_manifest(root)}
    if change == "tamper":
        (root / "image.tar").write_bytes(b"changed")
    elif change == "extra":
        (root / "unexpected-secret.txt").write_text("not admitted")
    elif change == "wrong_commit":
        evidence["commit"] = "b" * 40
    elif change == "wrong_manifest":
        evidence["tested_manifest_sha256"] = "0" * 64
    else:
        evidence["result"] = "fail"
    receipt = tmp_path / "acceptance.json"
    receipt.write_text(json.dumps(evidence))
    output = tmp_path / "release.zip"
    with pytest.raises(ValueError):
        package.seal(root, receipt, output)
    assert not output.exists()


def test_schema_adapter_refuses_unknown_source_without_touching_data(tmp_path):
    spec = importlib.util.spec_from_file_location("package_gate", SCRIPTS / "nct-package-schema-preflight.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    db = tmp_path / "analyzer.db"
    db.write_bytes(b"preserve exact bytes")
    with pytest.raises(ValueError, match="exact tested Phase 5"):
        gate.audit(db, "unknown", "b" * 40)
    assert db.read_bytes() == b"preserve exact bytes"


def test_bootstrap_checks_before_loading_or_replacing_application():
    script = (SCRIPTS / "nct-install-range.sh").read_text()
    assert script.index("sys.version_info >= (3,9)") < script.index("docker load")
    assert script.index("sha256sum -c PACKAGE-MANIFEST.sha256") < script.index("docker load")
    assert script.index("openssl verify -CAfile") < script.index("docker load")
    assert "certs/nct-lab-root.crt" in script
    assert "NCT_PACKAGE_RUNTIME_CLONE" in script


def test_missing_container_cannot_adopt_nonempty_retained_data(tmp_path):
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("Linux root container fixture")
    root, tools, persistent = tmp_path / "package", tmp_path / "bin", tmp_path / "retained"
    (root / "scripts").mkdir(parents=True)
    tools.mkdir()
    (persistent / "data").mkdir(parents=True)
    (persistent / "data/analyzer.db").write_bytes(b"preserve")
    shutil.copyfile(SCRIPTS / "nct-install-range.sh", root / "scripts/nct-install-range.sh")
    for name, body in {"docker": 'case "$1" in run) echo --pull;; info) exit 0;; inspect) exit 1;; load) echo UNEXPECTED_LOAD; exit 99;; esac', "systemctl": "exit 0", "ss": "echo State", "curl": "exit 99"}.items():
        path = tools / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)
    package.write_manifest(root)
    result = subprocess.run(["sh", str(root / "scripts/nct-install-range.sh"), "127.0.0.1"], capture_output=True, text=True,
        env={**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"], "NCT_PERSIST_ROOT": str(persistent)})
    assert result.returncode != 0
    assert "Retained evidence exists" in result.stderr
    assert "UNEXPECTED_LOAD" not in result.stdout
    assert (persistent / "data/analyzer.db").read_bytes() == b"preserve"


@pytest.mark.parametrize("corrupt", [False, True])
def test_full_upgrade_extracts_backup_before_candidate_can_start(tmp_path, corrupt):
    if os.name != "posix":
        pytest.skip("POSIX shell")
    data, backups = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    backups.mkdir()
    (data / "evidence").write_text("original evidence")
    archive = backups / "cold.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(data, arcname="data")
    if corrupt:
        archive.write_bytes(b"corrupt archive")
    before = backups / "before"
    before.write_text("original evidence")
    script = (SCRIPTS / "nct-upgrade.sh").read_text()
    start = script.index('{\n    verification_root=')
    body = script[start:script.index("backup_ready=yes", start)]
    harness = 'set -eu\nNCT_PACKAGE_RUNTIME_CLONE=qualified\nsnapshot() { cat "$DATA_DIR/evidence" > "$1"; }\ndie() { echo "$*" >&2; exit 1; }\n' + body + '\nprintf CANDIDATE_WOULD_START\n'
    result = subprocess.run(["sh", "-c", harness], capture_output=True, text=True, env={**os.environ,
        "DATA_DIR": str(data), "BACKUP_DIR": str(backups), "backup": str(archive), "before": str(before), "timestamp": "fixture"})
    assert ("CANDIDATE_WOULD_START" in result.stdout) is not corrupt
    assert (result.returncode == 0) is not corrupt
    assert (data / "evidence").read_text() == "original evidence"
