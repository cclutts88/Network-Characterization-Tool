#!/usr/bin/env python3
"""Read-only schema audit used before a Range upgrade changes saved NCT data."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from app.schema_compatibility import SchemaCompatibilityError, schema_upgrade_preflight


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path("/data/analyzer.db"))
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--expected-build-commit", required=True)
    args = parser.parse_args()
    result = schema_upgrade_preflight(
        args.db,
        expected_build_id=args.expected_build_id,
        expected_build_commit=args.expected_build_commit,
    )
    result["database_sha256"] = _sha256(args.db)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SchemaCompatibilityError) as exc:
        print(f"SCHEMA PREFLIGHT STOP: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
