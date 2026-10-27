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

LAUNCHERS = ("nct-start-docker.sh", "nct-start-compose.sh", "nct-start-legacy.sh", "nct-upgrade.sh", "nct-rollback-upgrade.sh", "nct-recover-unhealthy-upgrade.sh", "nct-range-direct-deploy.sh")
SOURCE_TAG = "0.16.0-range-test-20261013-phase3-r3"


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


def stage(source, output, image, console, commit, build_id):
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
    selected += ["scripts/install_nct_recovery.py", "scripts/nct_update_host.py", "scripts/nct_update_work.py", "scripts/build_nct_update.py", "scripts/setup-lab-https.sh",
        "compose.range.yaml", "compose.arkime.yaml", "Caddyfile", "docs/NCT_UPDATES_AND_RECOVERY.md", "docs/ARKIME_CONNECTOR_RANGE_SETUP.md", "docs/RANGE_UPDATER_PACKAGE.md"]
    bindings = []
    for name in selected:
        data = subprocess.check_output(["git", "-C", str(source), "show", commit + ":" + name])
        text = data.decode().replace("\r\n", "\n")
        if Path(name).name in LAUNCHERS:
            text = text.replace(SOURCE_TAG, build_id)
            if Path(name).name == "nct-recover-unhealthy-upgrade.sh":
                text = text.replace("f6ba1ad4a754b904511e3d726110d6fc35b9f237", commit)
        if name == "scripts/nct-upgrade.sh":
            if text.count("--required-source-version 6") != 1:
                raise ValueError("Upgrade template changed; review its source-version binding")
            text = text.replace("--required-source-version 6", "--required-source-version 7")
        package_name = "scripts/nct-schema-preflight-legacy.py" if name == "scripts/nct-schema-preflight.py" else name
        destination = output / package_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8", newline="\n")
        bindings.append({"source": name, "source_sha256": hashlib.sha256(data).hexdigest(), "package": package_name, "sha256": digest(destination)})
    # This full release accepts only its explicitly tested schema-7 source. Keep
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
        "images": images, "source_bindings": bindings, "schema_gate": "exact-phase5-r1-v7-to-v8-disposable-image-gate",
        "range_accepted": False, "kubernetes_updater_available": False}
    (output / "release.json").write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    write_manifest(output)
    return release


def seal(root, acceptance, output):
    tested = verify_manifest(root)
    result = json.loads(acceptance.read_text())
    release = json.loads((root / "release.json").read_text())
    if result.get("result") != "pass" or result.get("tested_manifest_sha256") != tested or result.get("commit") != release["commit"]:
        raise ValueError("Acceptance does not bind this exact staged package")
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
    return {"path": str(output.resolve()), "bytes": output.stat().st_size, "sha256": identity, "commit": release["commit"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    staging = sub.add_parser("stage")
    for name in ("source", "output"):
        staging.add_argument("--" + name, type=Path, required=True)
    for name in ("image", "console", "commit", "build-id"):
        staging.add_argument("--" + name, required=True)
    sealing = sub.add_parser("seal")
    for name in ("root", "acceptance", "output"):
        sealing.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    value = stage(args.source, args.output, args.image, args.console, args.commit, args.build_id) if args.action == "stage" else seal(args.root, args.acceptance, args.output)
    print(json.dumps(value, indent=2))
