#!/usr/bin/env python3
"""Verify locally loaded images against both modern and classic Docker identities."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path)
    args = parser.parse_args()
    release = json.loads(args.release.read_text(encoding="utf-8"))
    for name, metadata in release["images"].items():
        admitted_ids = {
            metadata.get("export_runtime_id"),
            metadata.get("archive_config_digest"),
        } - {None, ""}
        if not admitted_ids:
            raise ValueError(f"release has no immutable image identity for {name}")
        inspected = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", name],
            text=True,
            capture_output=True,
        )
        if inspected.returncode or inspected.stdout.strip() not in admitted_ids:
            raise ValueError(f"loaded image does not match the package: {name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Loaded image verification failed: {exc}")
