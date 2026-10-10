"""Prepare one fresh, deterministic Phase 0 browser benchmark data root."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import itertools
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid

try:
    from scripts.benchmark_phase0_core import _source_digest, _verify_corpus
    from scripts.benchmark_phase0_http import _common_signature, _stage_common, _stage_foundation
    from scripts.summarize_phase0_http_benchmark import _expected_common
except ModuleNotFoundError:  # Direct execution from the mounted scripts directory.
    from benchmark_phase0_core import _source_digest, _verify_corpus
    from benchmark_phase0_http import _common_signature, _stage_common, _stage_foundation
    from summarize_phase0_http_benchmark import _expected_common


FIXED_RUNTIME_TIME = "2030-04-01T00:00:00+00:00"


@contextmanager
def _deterministic_application_runtime():
    """Freeze benchmark-only IDs and clocks, then restore process globals."""
    original_uuid4 = uuid.uuid4
    sequence = itertools.count(1)
    uuid.uuid4 = lambda: uuid.UUID(int=next(sequence))
    patched = []
    for module in list(sys.modules.values()):
        name = getattr(module, "__name__", "")
        current = getattr(module, "utc_now", None)
        if name == "app" or name.startswith("app."):
            if callable(current):
                patched.append((module, current))
                module.utc_now = lambda: FIXED_RUNTIME_TIME
    try:
        yield
    finally:
        uuid.uuid4 = original_uuid4
        for module, current in patched:
            module.utc_now = current


def _rebase_artifact_paths(db_path: Path, data_root: Path) -> None:
    """Store the runtime /data path instead of the unique controller staging path."""
    with sqlite3.connect(db_path) as db:
        rows = db.execute("SELECT sha256, canonical_path FROM artifact_registry").fetchall()
        for digest, value in rows:
            source = Path(value)
            try:
                relative = source.relative_to(data_root)
            except ValueError as exc:
                raise ValueError("Prepared artifact path is outside the fresh data root") from exc
            destination = Path("/data") / relative
            db.execute(
                "UPDATE artifact_registry SET canonical_path = ? WHERE sha256 = ?",
                (destination.as_posix(), digest),
            )


def _freeze_preparation_metadata(db_path: Path) -> None:
    """Replace SQLite wall-clock defaults used only by disposable catalog rebuilds."""
    with sqlite3.connect(db_path) as db:
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "device_evidence_catalog_meta" in tables:
            db.execute(
                "UPDATE device_evidence_catalog_meta SET reconciled_at = ?",
                (FIXED_RUNTIME_TIME,),
            )


def prepare(
    target_root: Path,
    corpus_root: Path,
    data_root: Path,
    revision: str,
    foundation: bool,
) -> dict:
    if data_root.exists() or data_root.is_symlink():
        raise ValueError("Data directory must not exist before browser preparation")
    if len(revision) != 40 or any(value not in "0123456789abcdef" for value in revision.lower()):
        raise ValueError("Exact target revision is required")
    manifest, manifest_sha, corpus_bytes = _verify_corpus(corpus_root)
    source_sha, source_files = _source_digest(target_root)
    data_root.mkdir(parents=True)
    os.environ["ANALYZER_DATA_DIR"] = str(data_root)
    os.environ["NCT_AUTH_MODE"] = "disabled"
    sys.path.insert(0, str(target_root))
    from fastapi.testclient import TestClient
    import app.database as database
    import app.main as main
    import app.poc as poc

    main.start_derived_job_worker = lambda *_args, **_kwargs: None
    main.recover_scheduler_state = lambda: None
    main.schedule_worker = lambda stop: stop.wait()
    with _deterministic_application_runtime():
        with TestClient(main.app) as client:
            staged = _stage_common(manifest, corpus_root, data_root, poc, database)
            if foundation:
                main.reconcile_device_evidence_catalog(staged["db_path"], data_root / "device-configs")
                _stage_foundation(corpus_root, staged["db_path"])
                _rebase_artifact_paths(staged["db_path"], data_root)
            _freeze_preparation_metadata(staged["db_path"])
            current = client.get("/api/analysis/network").json()
            hunt = client.get("/api/hunting/network").json()
            topology = client.get("/api/network-map").json()
            reach = client.get("/api/reachability/context").json()
            signature = _common_signature(current, hunt, topology, reach)
            if signature != _expected_common(foundation=foundation):
                raise AssertionError("Prepared browser data failed the exact common oracle")
            for route in ("/analysis", "/hunting", "/reachability", "/network-map"):
                response = client.get(route)
                if response.status_code != 200 or "text/html" not in response.headers.get("content-type", ""):
                    raise AssertionError(f"Prewarm failed for {route}")

    marker = {
        "preparation_version": "phase0-browser-data:1",
        "revision": revision,
        "source_digest_sha256": source_sha,
        "source_file_count": source_files,
        "corpus_manifest_sha256": manifest_sha,
        "corpus_total_bytes": corpus_bytes,
        "foundation_capabilities": foundation,
        "staging_complete": True,
        "prewarm_complete": True,
        "staged": {"nmap_files": 9, "device_files": 4},
        "correctness": signature,
    }
    (data_root / ".phase0-browser-prepared.json").write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return marker


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--foundation-capabilities", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(
        args.target_root.resolve(), args.corpus.resolve(), args.data_root.resolve(),
        args.revision, args.foundation_capabilities,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
