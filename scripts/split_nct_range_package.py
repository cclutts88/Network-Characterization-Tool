#!/usr/bin/env python3
"""Prepare a sealed Range ZIP for a bounded, air-gapped file transfer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


PART_BYTES = 48 * 1024**2
_SAFE_ZIP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def _verified_sidecar(source: Path, expected: str) -> None:
    sidecar = source.with_suffix(source.suffix + ".sha256")
    if not sidecar.is_file() or sidecar.is_symlink():
        raise ValueError("The sealed ZIP needs its adjacent .sha256 file before splitting")
    lines = [line.strip() for line in sidecar.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("The sealed ZIP checksum file must contain exactly one record")
    fields = lines[0].split()
    if not fields or fields[0] != expected:
        raise ValueError("The sealed ZIP checksum does not match the ZIP")
    if len(fields) > 1 and fields[-1].lstrip("*") != source.name:
        raise ValueError("The sealed ZIP checksum names a different file")


def _verify_local_reconstruction(
    output: Path,
    parts: list[dict[str, object]],
    expected: str,
    size: int,
) -> None:
    rebuilt = hashlib.sha256()
    rebuilt_bytes = 0
    for part in parts:
        path = output / str(part["file"])
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Generated transfer piece is unavailable: {path.name}")
        if path.stat().st_size != part["bytes"] or digest(path) != part["sha256"]:
            raise ValueError(f"Generated transfer piece failed verification: {path.name}")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024**2), b""):
                rebuilt.update(block)
                rebuilt_bytes += len(block)
    if rebuilt_bytes != size or rebuilt.hexdigest() != expected:
        raise ValueError("Generated transfer pieces do not rebuild the sealed ZIP exactly")


def _join_script(
    source: Path,
    parts: list[dict[str, object]],
    expected: str,
    transfer_id: str,
    source_size: int,
    transfer_record_sha256: str,
    readme_sha256: str,
) -> str:
    checksums = "\n".join(f"{part['sha256']}  {part['file']}" for part in parts)
    expected_names = " ".join(str(part["file"]) for part in parts)
    inputs = " ".join(f'"$PARTS/{part["file"]}"' for part in parts)
    return f'''#!/bin/sh
set -eu
umask 077

PARTS=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
OUT_ARG=${{1:-$PARTS}}
if [ ! -d "$OUT_ARG" ] || [ -L "$OUT_ARG" ]; then
  printf '%s\n' "HALT: Output folder does not exist or is a link: $OUT_ARG" >&2
  exit 1
fi
OUT=$(CDPATH= cd -- "$OUT_ARG" && pwd -P)
FINAL="$OUT/{source.name}"
EXPECTED={expected}
EXPECTED_BYTES={source_size}
EXPECTED_PARTS="{expected_names}"
TRANSFER_RECORD="$PARTS/TRANSFER-CHECKSUMS.json"
README="$PARTS/READ-ME-FIRST.txt"

printf '%s\n' 'NCT Range transfer {transfer_id}'
printf '%s\n' '[1/4] Checking that this folder contains the exact transfer set...'
for identity_file in "$TRANSFER_RECORD" "$README"; do
  if [ ! -f "$identity_file" ] || [ -L "$identity_file" ]; then
    printf '%s\n' "HALT: $(basename -- "$identity_file") is missing or is not a regular file." >&2
    exit 1
  fi
done
if [ "$(sha256sum "$TRANSFER_RECORD" | cut -d " " -f 1)" != "{transfer_record_sha256}" ]; then
  printf '%s\n' 'HALT: TRANSFER-CHECKSUMS.json belongs to a different or damaged transfer set.' >&2
  exit 1
fi
if [ "$(sha256sum "$README" | cut -d " " -f 1)" != "{readme_sha256}" ]; then
  printf '%s\n' 'HALT: READ-ME-FIRST.txt belongs to a different or damaged transfer set.' >&2
  exit 1
fi
actual_count=0
for candidate in "$PARTS"/*.zip.part*; do
  [ -e "$candidate" ] || [ -L "$candidate" ] || continue
  name=$(basename -- "$candidate")
  case " $EXPECTED_PARTS " in
    *" $name "*) ;;
    *) printf '%s\n' "HALT: Unexpected transfer piece from another set: $name" >&2; exit 1 ;;
  esac
  actual_count=$((actual_count + 1))
done
for name in $EXPECTED_PARTS; do
  if [ ! -f "$PARTS/$name" ] || [ -L "$PARTS/$name" ]; then
    printf '%s\n' "HALT: Expected transfer piece is missing or is not a regular file: $name" >&2
    exit 1
  fi
done
if [ "$actual_count" -ne {len(parts)} ]; then
  printf '%s\n' "HALT: Expected {len(parts)} transfer pieces but found $actual_count." >&2
  exit 1
fi

printf '%s\n' '[2/4] Verifying every transfer piece...'
(cd "$PARTS" && sha256sum -c - <<'NCT_PART_CHECKSUMS'
{checksums}
NCT_PART_CHECKSUMS
)

if [ -e "$FINAL" ] || [ -L "$FINAL" ]; then
  if [ ! -L "$FINAL" ] && [ -f "$FINAL" ] && [ "$(sha256sum "$FINAL" | cut -d " " -f 1)" = "$EXPECTED" ]; then
    printf '%s\n' '[3/4] Existing complete ZIP is already correct; rebuild skipped.'
    printf '%s\n' "[4/4] PASS: Verified pieces and complete ZIP: $FINAL"
    printf '%s\n' 'No file was replaced. NCT has not been installed or updated.'
    exit 0
  fi
  printf '%s\n' "HALT: A different file or link already exists at $FINAL. It has been preserved." >&2
  exit 1
fi

printf '%s\n' "[3/4] Rebuilding the original $EXPECTED_BYTES-byte ZIP..."
TEMP=$(mktemp "$OUT/.nct-transfer-join.XXXXXX")
trap 'rm -f -- "$TEMP"' EXIT HUP INT TERM
cat {inputs} > "$TEMP"
if [ "$(sha256sum "$TEMP" | cut -d " " -f 1)" != "$EXPECTED" ]; then
  printf '%s\n' 'HALT: Combined ZIP checksum failed. Keep the pieces and retry.' >&2
  exit 1
fi
if [ "$(wc -c < "$TEMP" | tr -d ' ')" -ne "$EXPECTED_BYTES" ]; then
  printf '%s\n' 'HALT: Combined ZIP size is wrong. Keep the pieces and retry.' >&2
  exit 1
fi
ln -T -- "$TEMP" "$FINAL" || {{
  printf '%s\n' 'HALT: The output name became occupied; the existing file was preserved.' >&2
  exit 1
}}

printf '%s\n' "[4/4] PASS: Complete ZIP rebuilt and verified: $FINAL"
printf '%s\n' 'NCT has not been installed or updated.'
'''


def _instructions(
    source: Path,
    parts: list[dict[str, object]],
    expected: str,
    transfer_id: str,
    source_size: int,
) -> str:
    upload_names = [str(part["file"]) for part in parts] + [
        "JOIN-NCT.sh",
        "READ-ME-FIRST.txt",
        "TRANSFER-CHECKSUMS.json",
    ]
    upload_list = "\n".join(f"  - {name}" for name in upload_names)
    extracted = source.stem + "-extracted"
    return f'''NCT Range transfer {transfer_id}

Purpose
  Move one already sealed NCT package through a file uploader that rejects the
  complete ZIP. This transfer does not install, update, reset, or delete NCT.

Folder rule
  Create one new empty controller folder for this release. All pieces belong
  together in that one folder; do not put each piece in its own folder and do
  not mix pieces from an older release into it.

1. Upload every file in the transfer folder to that controller folder. The
   transfer folder contains exactly these {len(upload_names)} files:
{upload_list}

  Do not leave TRANSFER-CHECKSUMS.json behind: it lets the controller joiner
  confirm that the visible transfer identity matches the pieces. No separate
  checksum upload is required; JOIN-NCT.sh contains the expected checksum for
  every piece and for the complete ZIP.

2. In that controller folder, run:
     sh JOIN-NCT.sh

3. Wait for all four numbered stages and this final result:
     PASS: Complete ZIP rebuilt and verified

  If the script prints HALT, leave the pieces in place and correct the named
  missing, extra, corrupt, or conflicting file. Do not install a partial ZIP.

4. After PASS, keep the pieces and ZIP until Range acceptance is complete.
   Extract into a new folder, then read START-HERE.md:
     mkdir {extracted}
     unzip -q {source.name} -d {extracted}
     cd {extracted}/NCT-Air-Gapped-Range-Deployment
     less START-HERE.md

Complete ZIP
  File: {source.name}
  Bytes: {source_size}
  SHA-256: {expected}
'''


def split_package(source, output=None, *, part_bytes=PART_BYTES):
    source = Path(source)
    if (
        source.is_symlink()
        or not source.is_file()
        or source.suffix.lower() != ".zip"
        or source.stat().st_size == 0
    ):
        raise ValueError("Choose a nonempty sealed ZIP")
    source = source.resolve()
    if not 0 < part_bytes <= PART_BYTES:
        raise ValueError("Transfer pieces must be at most 48 MiB")
    if not _SAFE_ZIP_NAME.fullmatch(source.name):
        raise ValueError("ZIP filename must use simple letters, numbers, dots, dashes or underscores")

    source_size = source.stat().st_size
    expected = digest(source)
    _verified_sidecar(source, expected)
    transfer_id = expected[:12]
    output = Path(output) if output else source.with_name(source.stem + "-Transfer-Parts")
    output.mkdir(parents=True, exist_ok=False)

    part_count = (source_size + part_bytes - 1) // part_bytes
    width = max(2, len(str(part_count)))
    parts: list[dict[str, object]] = []
    with source.open("rb") as stream:
        for number in range(1, part_count + 1):
            block = stream.read(part_bytes)
            if not block:
                raise ValueError("The sealed ZIP changed while transfer pieces were created")
            name = f"{source.name}.part{number:0{width}d}"
            with (output / name).open("xb") as part:
                part.write(block)
            parts.append(
                {
                    "file": name,
                    "bytes": len(block),
                    "sha256": hashlib.sha256(block).hexdigest(),
                }
            )
        if stream.read(1):
            raise ValueError("The sealed ZIP changed while transfer pieces were created")

    if source.stat().st_size != source_size or digest(source) != expected:
        raise ValueError("The source ZIP changed during splitting; transfer set is not qualified")
    _verify_local_reconstruction(output, parts, expected, source_size)

    required_uploads = [
        *(part["file"] for part in parts),
        "JOIN-NCT.sh",
        "READ-ME-FIRST.txt",
        "TRANSFER-CHECKSUMS.json",
    ]
    controller_record = {
        "contract": "nct-transfer-parts-v1",
        "transfer_id": transfer_id,
        "zip": source.name,
        "zip_bytes": source_size,
        "zip_sha256": expected,
        "max_piece_bytes": part_bytes,
        "part_count": len(parts),
        "parts": parts,
        "required_controller_uploads": required_uploads,
        "local_reconstruction_verified": True,
        "join_script": "JOIN-NCT.sh",
    }
    record_path = output / "TRANSFER-CHECKSUMS.json"
    record_path.write_text(
        json.dumps(controller_record, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    readme_path = output / "READ-ME-FIRST.txt"
    readme_path.write_text(
        _instructions(source, parts, expected, transfer_id, source_size),
        encoding="utf-8",
        newline="\n",
    )
    join_path = output / "JOIN-NCT.sh"
    join_path.write_text(
        _join_script(
            source,
            parts,
            expected,
            transfer_id,
            source_size,
            digest(record_path),
            digest(readme_path),
        ),
        encoding="utf-8",
        newline="\n",
    )

    result = {
        **controller_record,
        "transfer_record_sha256": digest(record_path),
        "join_script_sha256": digest(join_path),
        "readme_sha256": digest(readme_path),
    }
    return {"directory": str(output.resolve()), **result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prepare a sealed NCT Range ZIP as verified pieces no larger than 48 MiB."
    )
    parser.add_argument("zip", type=Path, help="Sealed Range ZIP with an adjacent .zip.sha256 file")
    parser.add_argument("--output", type=Path, help="New folder for this release's transfer set")
    args = parser.parse_args()
    print(json.dumps(split_package(args.zip, args.output), indent=2))
