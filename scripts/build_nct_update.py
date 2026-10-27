#!/usr/bin/env python3
"""Build a single-file, tagless NCT GUI update package from a local Docker image."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

from nct_update_host import CONTRACT, canonical, digest_file, validate_image_archive


def build(image, sources, output):
    metadata = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
    env = dict(value.split("=", 1) for value in metadata["Config"]["Env"] if "=" in value)
    with tempfile.TemporaryDirectory(prefix="nct-update-") as temporary:
        root = Path(temporary)
        subprocess.run(["docker", "save", "-o", str(root / "source.tar"), metadata["Id"]], check=True)
        with tarfile.open(root / "source.tar") as source, tarfile.open(root / "image.tar", "w", format=tarfile.GNU_FORMAT) as target:
            manifests = json.load(source.extractfile("manifest.json"))
            if len(manifests) != 1:
                raise ValueError("Export must contain exactly one image")
            manifest = manifests[0]
            manifest["RepoTags"] = []
            content = canonical([manifest])
            member = tarfile.TarInfo("manifest.json")
            member.size = len(content)
            target.addfile(member, io.BytesIO(content))
            for name in dict.fromkeys([manifest["Config"], *manifest["Layers"]]):
                member = source.getmember(name)
                target.addfile(member, source.extractfile(member))
        with tarfile.open(root / "image.tar") as archive:
            image_config_id = "sha256:" + hashlib.sha256(archive.extractfile(manifest["Config"]).read()).hexdigest()
        validate_image_archive(root / "image.tar", image_config_id)
        release = {"contract": CONTRACT, "image_config_id": image_config_id,
            "image_sha256": digest_file(root / "image.tar"), "build_id": env["NCT_BUILD_ID"],
            "build_commit": env["NCT_BUILD_COMMIT"], "source_builds": sources}
        content = canonical(release)
        with output.open("xb") as destination, tarfile.open(fileobj=destination, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
            member = tarfile.TarInfo("release.json")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
            archive.add(root / "image.tar", arcname="image.tar", recursive=False)
    return {"path": str(output.resolve()), "sha256": digest_file(output), **release}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-build", action="append", required=True, help="Exact tested source BUILD_ID@COMMIT; repeat for each source")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sources = []
    for item in args.source_build:
        build_id, commit = item.rsplit("@", 1)
        sources.append({"build_id": build_id, "build_commit": commit})
    print(json.dumps(build(args.image, sources, args.output), indent=2))
