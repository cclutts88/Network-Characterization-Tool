#!/usr/bin/env python3
"""Stage and seal a full offline release from committed, allowlisted sources."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile
import importlib.util

LAUNCHERS = ("nct-start-docker.sh", "nct-start-compose.sh", "nct-start-legacy.sh", "nct-upgrade.sh", "nct-rollback-upgrade.sh", "nct-recover-unhealthy-upgrade.sh", "nct-range-direct-deploy.sh")
SOURCE_TAG = "0.16.0-range-test-20261013-phase3-r3"
R4_SOURCE = {"build_id": "0.16.0-range-test-20261102-recovery-r4", "build_commit": "937954bc03e4b21c3e93d7430321a918d8bc59a0"}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            value.update(block)
    return value.hexdigest()


def command(*args):
    return subprocess.check_output(args).decode().strip()


def write_manifest(root):
    files = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "PACKAGE-MANIFEST.sha256")
    (root / "PACKAGE-MANIFEST.sha256").write_text("".join(f"{digest(path)}  {path.relative_to(root).as_posix()}\n" for path in files), encoding="utf-8", newline="\n")


def verify_manifest(root):
    expected = {}
    for line in (root / "PACKAGE-MANIFEST.sha256").read_text().splitlines():
        identity, name = line.split("  ", 1)
        path = root / name
        if not re.fullmatch("[0-9a-f]{64}", identity) or Path(name).is_absolute() or ".." in Path(name).parts or name in expected or path.is_symlink() or not path.is_file():
            raise ValueError("Invalid package manifest")
        expected[name] = identity
        if digest(path) != identity:
            raise ValueError("Package content changed: " + name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name != "PACKAGE-MANIFEST.sha256"}
    if set(expected) != actual:
        raise ValueError("Unlisted or missing package content")
    return digest(root / "PACKAGE-MANIFEST.sha256")


def normalize_export(raw, output):
    with tarfile.open(raw) as source, tarfile.open(output, "w", format=tarfile.GNU_FORMAT) as target:
        entries = json.load(source.extractfile("manifest.json"))
        merged = {}
        for entry in entries:
            key = (entry["Config"], tuple(entry["Layers"]))
            if key not in merged:
                merged[key] = {"Config": entry["Config"], "Layers": entry["Layers"], "RepoTags": []}
            merged[key]["RepoTags"] = sorted(set(merged[key]["RepoTags"] + (entry.get("RepoTags") or [])))
        entries = list(merged.values())
        payload = json.dumps(entries, sort_keys=True).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(payload)
        target.addfile(info, io.BytesIO(payload))
        for name in dict.fromkeys(name for item in entries for name in [item["Config"], *item["Layers"]]):
            member = source.getmember(name)
            if not member.isfile():
                raise ValueError("Docker export contains a non-file image member")
            target.addfile(member, source.extractfile(member))
        identities = {tag: "sha256:" + hashlib.sha256(source.extractfile(item["Config"]).read()).hexdigest() for item in entries for tag in item["RepoTags"]}
        return identities


def stage(source, output, image, console, commit, build_id, existing_r4=False, fresh_install=False):
    if image != "network-characterization-tool:" + build_id or console != "nct-recovery-console:" + build_id:
        raise ValueError("Image tags must match the full package's bound launcher names")
    if command("git", "-C", str(source), "rev-parse", "HEAD") != commit or command("git", "-C", str(source), "status", "--porcelain"):
        raise ValueError("Build from the exact clean committed source")
    images = {}
    for name in (image, console, "caddy:2-alpine"):
        metadata = json.loads(command("docker", "image", "inspect", name))[0]
        if name != "caddy:2-alpine":
            env = dict(value.split("=", 1) for value in metadata["Config"]["Env"] if "=" in value)
            if env.get("NCT_BUILD_ID") != build_id or env.get("NCT_BUILD_COMMIT") != commit:
                raise ValueError("Release image does not match the committed package source")
        images[name] = {"export_runtime_id": metadata["Id"]}
    output.mkdir(parents=True, exist_ok=False)
    (output / "scripts").mkdir()
    (output / "docs").mkdir()
    (output / "offline-images").mkdir()
    tracked = command("git", "-C", str(source), "ls-tree", "-r", "--name-only", commit).splitlines()
    selected = [name for name in tracked if name.startswith("scripts/nct-") and Path(name).suffix in {".py", ".sh"}]
    selected += ["scripts/nct-package-sources.json", "scripts/install_nct_recovery.py", "scripts/nct_update_host.py", "scripts/nct_update_work.py", "scripts/nct_fresh_handoff.py", "scripts/build_nct_update.py", "scripts/build_nct_range_package.py", "scripts/setup-lab-https.sh",
        "compose.range.yaml", "compose.arkime.yaml", "Caddyfile", "docs/NCT_UPDATES_AND_RECOVERY.md", "docs/ARKIME_CONNECTOR_RANGE_SETUP.md", "docs/RANGE_UPDATER_PACKAGE.md", "scripts/split_nct_range_package.py"]
    bindings = []
    for name in selected:
        data = subprocess.check_output(["git", "-C", str(source), "show", commit + ":" + name])
        text = data.decode().replace("\r\n", "\n")
        if Path(name).name in LAUNCHERS:
            text = text.replace(SOURCE_TAG, build_id)
            if Path(name).name == "nct-recover-unhealthy-upgrade.sh":
                text = text.replace("f6ba1ad4a754b904511e3d726110d6fc35b9f237", commit)
                text = text.replace('scripts/nct-schema-preflight.py', 'scripts/nct-schema-preflight-legacy.py')
        if name == "scripts/nct-upgrade.sh":
            if text.count('--required-source-version "${NCT_REQUIRED_SOURCE_VERSION:-6}"') != 1:
                raise ValueError("Upgrade template changed; review its source-version binding")
            text = text.replace('--required-source-version "${NCT_REQUIRED_SOURCE_VERSION:-6}"', '--required-source-version "${NCT_REQUIRED_SOURCE_VERSION:-7}"')
        package_name = "scripts/nct-schema-preflight-legacy.py" if name == "scripts/nct-schema-preflight.py" else name
        destination = output / package_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8", newline="\n")
        bindings.append({"source": name, "source_sha256": hashlib.sha256(data).hexdigest(), "package": package_name, "sha256": digest(destination)})
    # This full release accepts only its explicitly tested schema-7/8 sources. Keep
    # the legacy public preflight beside the adapter for traceability/fallback.
    (output / "scripts/nct-schema-preflight.py").write_bytes((output / "scripts/nct-package-schema-preflight.py").read_bytes())
    (output / "START-HERE.md").write_bytes((output / "docs/RANGE_UPDATER_PACKAGE.md").read_bytes())
    for source_name, destination_name in (("scripts/nct-package-schema-preflight.py", "scripts/nct-schema-preflight.py"), ("docs/RANGE_UPDATER_PACKAGE.md", "START-HERE.md")):
        original_data = subprocess.check_output(["git", "-C", str(source), "show", commit + ":" + source_name])
        bindings.append({"source": source_name, "source_sha256": hashlib.sha256(original_data).hexdigest(), "package": destination_name, "sha256": digest(output / destination_name)})
    raw = output / "offline-images/source-export.tmp"
    archive = output / "offline-images/nct-range-images.tar"
    try:
        subprocess.run(["docker", "save", "-o", str(raw), image, console, "caddy:2-alpine"], check=True)
        for name, identity in normalize_export(raw, archive).items():
            images[name]["archive_config_digest"] = identity
    finally:
        raw.unlink(missing_ok=True)
    (archive.with_suffix(".tar.sha256")).write_text(digest(archive) + "  nct-range-images.tar\n", encoding="utf-8")
    release = {"contract": "nct-full-range-package-v1", "build_id": build_id, "commit": commit,
        "branch": "foundation/evidence-engine-v2", "application_image": image, "console_image": console,
        "images": images, "source_bindings": bindings, "schema_gate": "exact-supported-v7-or-v8-to-v8-disposable-image-gate",
        "supported_sources": json.loads((output / "scripts/nct-package-sources.json").read_text()),
        "range_accepted": False, "kubernetes_updater_available": False}
    from build_nct_update import build
    r3 = {"build_id":"0.16.0-range-test-20261029-recovery-r3", "build_commit":"03da1516face51403035e4292ac68cac9279dd65"}
    # Terminal installer acceptance is not GUI-update acceptance.
    sources = [R4_SOURCE] if existing_r4 else [r3]
    update = build(image, sources, output / ("nct-update-" + build_id + ".tar.gz"))
    release["gui_update"] = {"file":Path(update["path"]).name,"sha256":update["sha256"]}
    release["helper_upgrade_source"] = {**r3,
        "host_sha256":"00204d190fc8802d334f7c93834a3aa439792317f631db96ef01ebceeb4b00bc",
        "console_image_id":"sha256:4c1f8e8d5178710ee4f08ca891b356831ff631e30cccf4e8ef955c53731c94fd"}
    if existing_r4:
        # This kit deliberately qualifies one existing-installation path only.
        # Bundled emergency/terminal tools are not newly qualified install paths.
        del release["helper_upgrade_source"]
        for name in ("nct_update_host.py", "nct_update_work.py", "nct-range-data-check.py"):
            baseline = subprocess.check_output(["git", "-C", str(source), "show", R4_SOURCE["build_commit"] + ":scripts/" + name])
            if hashlib.sha256(baseline.replace(b'\r\n', b'\n')).hexdigest() != digest(output / "scripts" / name):
                raise ValueError("Existing-R4 mode requires unchanged recovery helper files")
        release["supported_sources"] = [{"build_id": R4_SOURCE["build_id"], "commit": R4_SOURCE["build_commit"], "schema_version": 8}]
        registry = output / "scripts/nct-package-sources.json"
        registry.write_text(json.dumps(release["supported_sources"], indent=2) + "\n", encoding="utf-8")
        for binding in bindings:
            if binding["package"] == "scripts/nct-package-sources.json":
                binding["sha256"] = digest(registry)
        release["schema_gate"] = "existing-r4-gui-update-with-unchanged-helper-and-console"
        release["existing_helper_reuse"] = {**R4_SOURCE,
            "files": {name: digest(output / "scripts" / name) for name in ("nct_update_host.py", "nct_update_work.py", "nct-range-data-check.py")},
            "console_config_digest": "sha256:0606260094f4a81e4227c9809fa8e5c633ad99b88bfe2b3a18c7f3e9febfff7c"}
        release["terminal_install_qualified"] = False
        instructions = subprocess.check_output(["git", "-C", str(source), "show", commit + ":docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md"])
        (output / "START-HERE.md").write_bytes(instructions)
        release["source_bindings"] = [b for b in bindings if b["package"] != "START-HERE.md"]
        release["source_bindings"].append({"source": "docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md", "source_sha256": hashlib.sha256(instructions).hexdigest(), "package": "START-HERE.md", "sha256": digest(output / "START-HERE.md")})
    if fresh_install:
        release["terminal_upgrade_qualified"] = release.pop("terminal_install_qualified", False)
        release["fresh_install"] = {"route":"standalone-docker-empty-host-v1", "launcher":"scripts/nct-install-range.sh", "mode":"fresh", "check_mode":"check-fresh"}
        instructions = subprocess.check_output(["git", "-C", str(source), "show", commit + ":docs/RANGE_FRESH_INSTALL.md"])
        (output / "START-HERE.md").write_bytes(instructions)
        # Keep the optional exact-R4 update instructions separately.
        if existing_r4:
            update_instructions = subprocess.check_output(["git", "-C", str(source), "show", commit + ":docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md"])
            (output / "docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md").write_bytes(update_instructions)
            release["source_bindings"].append({"source":"docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md", "source_sha256":hashlib.sha256(update_instructions).hexdigest(), "package":"docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md", "sha256":digest(output / "docs/RANGE_EVIDENCE_LIBRARY_UPDATE.md")})
        release["source_bindings"] = [b for b in release["source_bindings"] if b["package"] != "START-HERE.md"]
        release["source_bindings"].append({"source":"docs/RANGE_FRESH_INSTALL.md", "source_sha256":hashlib.sha256(instructions).hexdigest(), "package":"START-HERE.md", "sha256":digest(output / "START-HERE.md")})
    (output / "release.json").write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    write_manifest(output)
    return release


def seal(root, acceptance, output):
    tested = verify_manifest(root)
    result = json.loads(acceptance.read_text())
    release = json.loads((root / "release.json").read_text())
    if result.get("result") != "pass" or result.get("tested_manifest_sha256") != tested or result.get("commit") != release["commit"]:
        raise ValueError("Acceptance does not bind this exact staged package")
    if not release.get("supported_sources"):
        raise ValueError("Release must declare its supported upgrade sources")
    if release["supported_sources"]:
        expected = {(s["build_id"], s["commit"], s["schema_version"]) for s in release["supported_sources"]}
        if len(expected) != len(release["supported_sources"]) or any(not b or len(c) != 40 or v not in (7, 8) for b, c, v in expected):
            raise ValueError("Invalid or duplicate supported upgrade sources")
        seen = set()
        for proof in result.get("source_results", []):
            identity = (proof.get("source_build"), proof.get("source_commit"), proof.get("source_schema_version"))
            if identity not in expected or identity in seen or proof.get("result") != "pass" or proof.get("commit") != release["commit"] or proof.get("tested_manifest_sha256") != tested or proof.get("images") != release["images"]:
                raise ValueError("Source acceptance is missing, duplicated or bound to different package/images")
            seen.add(identity)
        if seen != expected:
            raise ValueError("Every supported source needs its own exact-package acceptance")
    if release.get("helper_upgrade_source"):
        proof = result.get("helper_upgrade_result", {})
        source = release["helper_upgrade_source"]
        required = ("ca_verified", "app_unchanged_by_helper_upgrade", "existing_receipt_preserved",
                    "existing_account_preserved", "app_update_and_backup_restore", "later_evidence_preserved", "crash_after_create_recovered")
        if (proof.get("result") != "pass" or proof.get("tested_manifest_sha256") != tested
            or proof.get("commit") != release["commit"] or proof.get("images") != release["images"]
            or proof.get("source_build") != source["build_id"] or proof.get("source_commit") != source["build_commit"]
            or proof.get("old_helper_sha256") != source["host_sha256"] or proof.get("old_console") != source["console_image_id"]
            or not all(proof.get(k) is True for k in required)):
            raise ValueError("The exact installed-helper upgrade needs its own qualified acceptance")
    if release.get("existing_helper_reuse"):
        proof = result.get("existing_helper_reuse", {})
        required = ("ca_verified", "update_verified", "restore_verified", "controlled_failure", "existing_account_preserved", "evidence_unchanged", "library_verified", "helper_unchanged", "console_unchanged", "update_pause_absent")
        if (proof.get("source") != release["existing_helper_reuse"] or proof.get("tested_manifest_sha256") != tested
            or proof.get("commit") != release["commit"] or proof.get("gui_update_sha256") != release["gui_update"]["sha256"]
            or proof.get("images") != release["images"] or not all(proof.get(k) is True for k in required)):
            raise ValueError("The exact existing-R4 GUI update needs its own qualified acceptance")
    if release.get("fresh_install"):
        proof = result.get("fresh_install", {})
        required = ("empty_storage_verified", "fresh_admission_refusals", "interactive_admin_setup", "ca_verified", "exact_application", "exact_console", "recovery_handoff", "sign_in_final_restart", "stop_start_persistence", "helper_service_restart", "console_stops_after_return", "library_import_and_device_downloads")
        if (proof.get("route") != release["fresh_install"] or proof.get("tested_manifest_sha256") != tested
            or proof.get("commit") != release["commit"] or proof.get("images") != release["images"]
            or proof.get("result") != "pass" or not all(proof.get(k) is True for k in required)):
            raise ValueError("Fresh installation needs its own exact-package qualification")
    (root / "VALIDATION.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_manifest(root)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, "NCT-Air-Gapped-Range-Deployment/" + path.relative_to(root).as_posix())
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("Final transfer ZIP failed verification")
    identity = digest(output)
    output.with_suffix(output.suffix + ".sha256").write_text(identity + "  " + output.name + "\n", encoding="utf-8")
    result = {"path": str(output.resolve()), "bytes": output.stat().st_size, "sha256": identity, "commit": release["commit"]}
    spec = importlib.util.spec_from_file_location("nct_transfer_parts", Path(__file__).with_name("split_nct_range_package.py"))
    transfer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transfer)
    if output.stat().st_size > transfer.PART_BYTES:
        result["transfer"] = transfer.split_package(output)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    staging = sub.add_parser("stage")
    for name in ("source", "output"):
        staging.add_argument("--" + name, type=Path, required=True)
    for name in ("image", "console", "commit", "build-id"):
        staging.add_argument("--" + name, required=True)
    staging.add_argument("--existing-r4", action="store_true")
    staging.add_argument("--fresh-install", action="store_true")
    sealing = sub.add_parser("seal")
    for name in ("root", "acceptance", "output"):
        sealing.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    value = stage(args.source, args.output, args.image, args.console, args.commit, args.build_id, args.existing_r4, args.fresh_install) if args.action == "stage" else seal(args.root, args.acceptance, args.output)
    print(json.dumps(value, indent=2))
