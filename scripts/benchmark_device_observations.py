"""Opt-in benchmark for disposable scoped device-interface observations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import time
import tracemalloc

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import derived_jobs as jobs
from app import device_configs
from app.device_observations import (
    assign_device_scope,
    extract_device_interface_addresses,
    get_device_interface_receipts,
)
from app.main import app
from app.network_scopes import create_network_scope


def configuration(interface_count: int) -> str:
    lines = []
    for index in range(interface_count):
        second = (index // (250 * 250)) % 250
        third = (index // 250) % 250
        fourth = index % 250 + 1
        lines.extend([
            f"interface Ethernet{index}",
            f" ip address 10.{second}.{third}.{fourth} 255.255.255.0",
        ])
    return "\n".join(lines) + "\n"


def run(interface_count: int, page_size: int) -> dict:
    text = configuration(interface_count)
    tracemalloc.start()
    extraction_started = time.perf_counter()
    extracted = extract_device_interface_addresses(text)
    extraction_seconds = time.perf_counter() - extraction_started
    extraction_peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    with tempfile.TemporaryDirectory(prefix="nct-device-observation-benchmark-") as raw:
        root = Path(raw)
        db_path = root / "analyzer.db"
        device_configs.DB_PATH = db_path
        device_configs.CONFIG_DIR = root / "device-configs"
        jobs.start_derived_job_worker = lambda *args, **kwargs: None
        with TestClient(app) as client:
            response = client.post(
                "/api/device-configs/upload",
                data={
                    "operator": "synthetic-benchmark",
                    "originating_host": "benchmark",
                    "vendor": "cisco",
                    "device_type": "router",
                    "device_address": "192.0.2.200",
                    "device_name": "Synthetic benchmark device",
                },
                files={"result_file": ("benchmark.txt", text, "text/plain")},
            )
        response.raise_for_status()
        run_id = response.json()["run_id"]
        jobs.dispatch_next_pipeline_intake(db_path)
        jobs.run_next_derived_job(db_path, root)
        scope = create_network_scope(
            db_path, label="Synthetic benchmark scope", created_by="benchmark",
        )
        assign_device_scope(
            db_path, run_id=run_id, scope_id=scope["scope_id"], actor="benchmark",
            reason="Disposable benchmark context", whole_collection_confirmed=True,
        )
        jobs.dispatch_next_pipeline_intake(db_path)
        tracemalloc.start()
        publication_started = time.perf_counter()
        jobs.run_next_derived_job(db_path, root)
        publication_seconds = time.perf_counter() - publication_started
        publication_peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        page_started = time.perf_counter()
        first = get_device_interface_receipts(
            db_path, run_id, limit=page_size, offset=0,
        )
        first_page_seconds = time.perf_counter() - page_started
        last_offset = max(0, first["pagination"]["total"] - page_size)
        page_started = time.perf_counter()
        last = get_device_interface_receipts(
            db_path, run_id, limit=page_size, offset=last_offset,
        )
        last_page_seconds = time.perf_counter() - page_started
        return {
            "synthetic": True,
            "interface_count": interface_count,
            "configuration_bytes": len(text.encode()),
            "extracted_receipts": len(extracted["receipts"]),
            "published_receipts": first["pagination"]["total"],
            "page_size": page_size,
            "first_page_count": len(first["receipts"]),
            "last_page_count": len(last["receipts"]),
            "extraction_seconds": round(extraction_seconds, 6),
            "publication_seconds": round(publication_seconds, 6),
            "first_page_seconds": round(first_page_seconds, 6),
            "last_page_seconds": round(last_page_seconds, 6),
            "extraction_peak_bytes": extraction_peak,
            "publication_peak_bytes": publication_peak,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interfaces", type=int, default=1000)
    parser.add_argument("--page-size", type=int, default=100)
    args = parser.parse_args()
    if args.interfaces < 1 or not 1 <= args.page_size <= 250:
        raise SystemExit("interfaces must be positive and page size must be 1-250")
    print(json.dumps(run(args.interfaces, args.page_size), indent=2, sort_keys=True))
