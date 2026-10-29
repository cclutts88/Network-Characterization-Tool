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
    sources = json.loads((SCRIPTS / "nct-package-sources.json").read_text())
    (root / "release.json").write_text(json.dumps({"commit": "a" * 40, "supported_sources": sources, "images": {"app": "exact-id"}}))
    (root / "image.tar").write_bytes(b"exact image archive")
    package.write_manifest(root)
    return root


def evidence(root):
    release = json.loads((root / "release.json").read_text())
    result = {"result": "pass", "commit": release["commit"], "tested_manifest_sha256": package.verify_manifest(root)}
    result["source_results"] = [{**result, "source_build": s["build_id"], "source_commit": s["commit"], "source_schema_version": s["schema_version"], "images": release["images"]} for s in release["supported_sources"]]
    return result


def test_seal_binds_tested_files_and_includes_checksums_in_one_transfer(tmp_path):
    root = staged(tmp_path)
    receipt = tmp_path / "acceptance.json"
    receipt.write_text(json.dumps(evidence(root)))
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
    proof = evidence(root)
    if change == "tamper":
        (root / "image.tar").write_bytes(b"changed")
    elif change == "extra":
        (root / "unexpected-secret.txt").write_text("not admitted")
    elif change == "wrong_commit":
        proof["commit"] = "b" * 40
    elif change == "wrong_manifest":
        proof["tested_manifest_sha256"] = "0" * 64
    else:
        proof["result"] = "fail"
    receipt = tmp_path / "acceptance.json"
    receipt.write_text(json.dumps(proof))
    output = tmp_path / "release.zip"
    with pytest.raises(ValueError):
        package.seal(root, receipt, output)
    assert not output.exists()


@pytest.mark.parametrize("damage", ["missing", "duplicate", "image", "manifest", "commit", "version", "failed", "empty_registry", "missing_registry", "duplicate_registry"])
def test_seal_requires_both_exact_source_acceptances(tmp_path, damage):
    root = staged(tmp_path)
    proof = evidence(root)
    if damage.endswith("registry"):
        release = json.loads((root / "release.json").read_text())
        if damage == "missing_registry":
            del release["supported_sources"]
        elif damage == "empty_registry":
            release["supported_sources"] = []
        else:
            release["supported_sources"].append(release["supported_sources"][0])
        (root / "release.json").write_text(json.dumps(release))
        package.write_manifest(root)
        proof["tested_manifest_sha256"] = package.verify_manifest(root)
    elif damage == "missing":
        proof["source_results"].pop()
    elif damage == "duplicate":
        proof["source_results"].append(proof["source_results"][0])
    else:
        key = {"image": "images", "manifest": "tested_manifest_sha256", "commit": "commit", "version": "source_schema_version", "failed": "result"}[damage]
        proof["source_results"][0][key] = "changed"
    receipt = tmp_path / "proof.json"
    receipt.write_text(json.dumps(proof))
    with pytest.raises(ValueError):
        package.seal(root, receipt, tmp_path / "no.zip")


def test_standalone_gate_registry_matches_bootstrap_registry():
    spec = importlib.util.spec_from_file_location("gate", SCRIPTS / "nct-package-schema-preflight.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    assert gate.SOURCES == {(s["build_id"], s["commit"]): s["schema_version"] for s in json.loads((SCRIPTS / "nct-package-sources.json").read_text())}


@pytest.mark.parametrize("damage", [None, "origin", "ledger", "drift", "version", "wal"])
def test_schema8_gate_checks_migrated_ledger_without_changing_source(tmp_path, monkeypatch, damage):
    from test_schema_history_v8 import source_v7
    import app.schema_compatibility as schema
    from app.scan_history_index import init_scan_history_index_storage
    source = json.loads((SCRIPTS / "nct-package-sources.json").read_text())[1]
    monkeypatch.setattr(schema, "BUILD_ID", source["build_id"])
    monkeypatch.setattr(schema, "BUILD_COMMIT", source["commit"])
    db = source_v7(tmp_path)
    attempt = schema.begin_schema_migration(db)
    init_scan_history_index_storage(db)
    schema.complete_schema_migration(db, attempt)
    if damage in ("origin", "ledger", "drift"):
        with __import__("sqlite3").connect(db) as connection:
            if damage == "origin":
                connection.execute("UPDATE nct_schema_state SET originating_build_commit='unrecognized'")
            elif damage == "ledger":
                connection.execute("DELETE FROM nct_schema_migrations WHERE target_schema_version=4")
            else:
                connection.execute("CREATE TABLE unrelated(id)")
    if damage == "wal":
        db.with_name(db.name + "-wal").write_bytes(b"uncheckpointed")
    before = db.read_bytes()
    spec = importlib.util.spec_from_file_location("gate", SCRIPTS / "nct-package-schema-preflight.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    if damage:
        with pytest.raises((ValueError, schema.SchemaCompatibilityError)):
            gate.audit(db, source["build_id"], source["commit"], 7 if damage == "version" else 8)
    else:
        assert gate.audit(db, source["build_id"], source["commit"], 8)["schema_version"] == 8
    assert db.read_bytes() == before


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
    assert script.index("nct_select_recovery_python") < script.index("docker load")
    assert "sys.version_info >= (3, 9)" in (SCRIPTS / "nct-recovery-python.sh").read_text()
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
    for helper in ("nct-recovery-python.sh", "nct_update_host.py", "nct_update_work.py"):
        shutil.copyfile(SCRIPTS / helper, root / "scripts" / helper)
    for name, body in {"docker": 'case "$1" in run) echo --pull;; info) exit 0;; inspect) exit 1;; load) echo UNEXPECTED_LOAD; exit 99;; esac', "systemctl": "echo not-found", "ss": "echo State", "curl": "exit 99"}.items():
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


@pytest.mark.parametrize("existing", ["state", "config", "container", "service", "state_file", "install_file"])
def test_bootstrap_refuses_existing_helper_before_application_changes(tmp_path, existing):
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("Linux root container fixture")
    root, tools = tmp_path / "package", tmp_path / "bin"
    (root / "scripts").mkdir(parents=True)
    tools.mkdir()
    for name in ("nct-install-range.sh", "nct-recovery-python.sh", "nct_update_host.py", "nct_update_work.py"):
        shutil.copyfile(SCRIPTS / name, root / "scripts" / name)
    state, installed = tmp_path / "state", tmp_path / "installed"
    state.mkdir()
    installed.mkdir()
    if existing == "state":
        (state / "receipt").write_text("preserve receipt")
    if existing == "config":
        (installed / "config.json").write_text("preserve config")
    if existing == "state_file":
        state.rmdir()
        state.write_text("preserve state file")
    if existing == "install_file":
        installed.rmdir()
        installed.write_text("preserve install file")
    for name in ("docker", "systemctl", "openssl", "curl", "ss"):
        script = tools / name
        body = "echo " + ("loaded" if existing == "service" else "not-found") + "\n" if name == "systemctl" else ("exit 0\n" if name != "docker" or existing == "container" else "exit 1\n")
        script.write_text("#!/bin/sh\n" + body)
        script.chmod(0o700)
    result = subprocess.run(["sh", str(root / "scripts/nct-install-range.sh"), "127.0.0.1", "check"], capture_output=True, text=True,
        env={**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"], "NCT_RECOVERY_STATE_DIR": str(state), "NCT_RECOVERY_INSTALL_DIR": str(installed)})
    assert result.returncode != 0
    assert "already exists" in result.stderr or "already installed" in result.stderr or "occupied" in result.stderr
    if state.is_dir():
        assert sorted(p.name for p in state.iterdir()) == (["receipt"] if existing == "state" else [])
    else:
        assert state.read_text() == "preserve state file"


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
        "DATA_DIR": str(data), "BACKUP_DIR": str(backups), "backup": str(archive), "before": str(before), "timestamp": "fixture", "NCT_UPGRADE_PYTHON": sys.executable})
    assert ("CANDIDATE_WOULD_START" in result.stdout) is not corrupt
    assert (result.returncode == 0) is not corrupt
    assert (data / "evidence").read_text() == "original evidence"
