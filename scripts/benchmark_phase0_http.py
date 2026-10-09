"""Run one isolated in-process HTTP benchmark repeat against an NCT checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import time

try:
    from scripts.benchmark_phase0_core import (
        COMPARISON_STATISTIC,
        RELATIVE_LIMITS,
        _cpu_seconds,
        _peak_memory,
        _retained_state,
        _sha256,
        _source_digest,
        _validate_attestations,
        _verify_corpus,
    )
except ModuleNotFoundError:
    from benchmark_phase0_core import (
        COMPARISON_STATISTIC,
        RELATIVE_LIMITS,
        _cpu_seconds,
        _peak_memory,
        _retained_state,
        _sha256,
        _source_digest,
        _validate_attestations,
        _verify_corpus,
    )


RUNNER_VERSION = "phase0-http-benchmark:1"
COMMON_WORKLOADS = [
    "current:first", "current:repeat", "hunt:shared-reuse",
    "map:shared-reuse", "reach:shared-reuse",
]
FOUNDATION_WORKLOADS = [
    "current-page:first", "current-page:last", "current-ips:complete",
    "current-lfa:complete", "processed:scopes", "processed:first-page",
    "processed:last-page", "processed:endpoint", "processed:latest",
    "processed:services",
]
ABSOLUTE_LIMITS = {
    "whole_run_wall_seconds": 120.0,
    "whole_run_cpu_seconds": 120.0,
    "whole_run_peak_rss_bytes": 1_073_741_824,
    "common_request_wall_seconds": 30.0,
    "foundation_request_wall_seconds": 10.0,
    "bounded_response_bytes": 2_000_000,
    "complete_response_bytes": 25_000_000,
    "retained_data_root_bytes": 200_000_000,
}


def expected_workloads(foundation: bool) -> list[str]:
    return sorted(COMMON_WORKLOADS + (FOUNDATION_WORKLOADS if foundation else []))


def request_order(foundation: bool) -> list[str]:
    return COMMON_WORKLOADS + (FOUNDATION_WORKLOADS if foundation else [])


def _target_network(relative: str) -> str:
    values = {
        "nmap/small_tcp.xml": "10.10.0.0/24",
        "nmap/medium_udp.xml": "10.20.0.0/24",
        "nmap/history_before.xml": "10.30.0.0/24",
        "nmap/history_before_duplicate.xml": "10.30.0.0/24",
        "nmap/history_after.xml": "10.30.0.0/24",
        "nmap/large_segment_01.xml": "10.200.0.0/20",
        "nmap/large_segment_02.xml": "10.200.16.0/20",
        "nmap/large_segment_03.xml": "10.200.32.0/20",
        "nmap/large_segment_04.xml": "10.200.48.0/20",
    }
    return values[relative]


def _stage_common(manifest: dict, corpus: Path, data_root: Path, poc, database) -> dict:
    db_path = data_root / "analyzer.db"
    poc.init_poc_storage(db_path)
    nmap_paths = list(manifest["oracle"]["nmap_files"])
    history_order = {
        "nmap/history_before.xml": 1,
        "nmap/history_before_duplicate.xml": 2,
        "nmap/history_after.xml": 3,
    }
    for index, relative in enumerate(nmap_paths, start=10):
        sequence = history_order.get(relative, index)
        run_id = hashlib.sha256(relative.encode()).hexdigest()[:32]
        run_dir = data_root / "scan-runs" / run_id
        run_dir.mkdir(parents=True)
        content = (corpus / relative).read_bytes()
        (run_dir / "scan.xml").write_bytes(content)
        stamp = f"2030-01-{sequence:02d}T12:00:00+00:00"
        network = _target_network(relative)
        item = {
            "run_id": run_id,
            "display_name": f"Phase 0 {Path(relative).stem}",
            "created_at": stamp,
            "completed_at": stamp,
            "status": "completed",
            "operator": "phase0-benchmark",
            "reason": "Synthetic Phase 0 HTTP benchmark",
            "originating_host": "benchmark.invalid",
            "interface": "benchmark0",
            "profile": "safe",
            "targets": [network],
            "target_selection": {"manual_targets": [network]},
        }
        (run_dir / "manifest.json").write_text(json.dumps(item, sort_keys=True), encoding="utf-8")
        poc.insert_scan_run_manifest(item, db_path)

    for relative in manifest["oracle"]["devices"]["parsed_counts"]:
        run_id = hashlib.sha256(relative.encode()).hexdigest()[:32]
        run_dir = data_root / "device-configs" / run_id
        run_dir.mkdir(parents=True)
        filename = "uploaded-evidence.txt"
        shutil.copyfile(corpus / relative, run_dir / filename)
        item = {
            "run_id": run_id,
            "status": "uploaded",
            "operation": "manual_upload",
            "vendor": "cisco",
            "device_type": "router",
            "device_name": Path(relative).stem,
            "device_address": "192.0.2.1",
            "created_at": "2030-02-01T00:00:00+00:00",
            "completed_at": "2030-02-01T00:00:00+00:00",
            "retained_filename": filename,
            "output_complete": True,
            "commands": [],
        }
        (run_dir / "manifest.json").write_text(json.dumps(item, sort_keys=True), encoding="utf-8")
    return {"db_path": db_path, "nmap_files": len(nmap_paths), "device_files": 4}


def _stage_foundation(corpus: Path, db_path: Path) -> dict:
    from app.artifacts import register_artifact_bytes
    from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
    from app.evidence_scope_assignments import assign_artifact_scope
    from app.network_scopes import create_network_scope

    content = (corpus / "nmap" / "medium_udp.xml").read_bytes()
    observation = register_artifact_bytes(
        db_path=db_path, content=content, source_kind="nmap_import",
        source_ref="phase0:http:processed", original_filename="medium_udp.xml",
        actor="phase0-benchmark", observed_at="2030-03-01T00:00:00+00:00",
    )
    scope = create_network_scope(db_path, label="Phase 0 processed scope", created_by="phase0-benchmark")
    assignment = assign_artifact_scope(
        db_path, artifact_observation_id=observation["observation_id"],
        scope_id=scope["scope_id"], actor="phase0-benchmark",
        reason="Synthetic whole-file benchmark scope", whole_artifact_confirmed=True,
    )
    ingest_assigned_nmap_observation(
        db_path, expected_assignment_id=assignment["assignment_id"],
        linked_by="phase0-benchmark",
    )
    return {"scope_id": scope["scope_id"], "observation_id": observation["observation_id"]}


def _database_state(path: Path) -> dict:
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        tables = [
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        digest = hashlib.sha256()
        counts = {}
        table_digests = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in db.execute(f"PRAGMA table_info({quoted})").fetchall()]
            rows = db.execute(f"SELECT * FROM {quoted} ORDER BY rowid").fetchall()
            counts[table] = len(rows)
            table_digest = hashlib.sha256()
            header = json.dumps([table, columns], sort_keys=True).encode()
            digest.update(header)
            table_digest.update(header)
            for row in rows:
                normalized = [value.hex() if isinstance(value, bytes) else value for value in row]
                content = json.dumps(normalized, sort_keys=True, default=str).encode()
                digest.update(content)
                table_digest.update(content)
            table_digests[table] = table_digest.hexdigest()
    return {
        "logical_sha256": digest.hexdigest(),
        "main_file_sha256": _sha256(path.read_bytes()),
        "table_counts": counts,
        "table_digests": table_digests,
    }


def _evidence_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {"analyzer.db", "analyzer.db-wal", "analyzer.db-shm"}:
            continue
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(relative + b"\0" + _sha256(content).encode() + b"\0")
    return digest.hexdigest()


def _request(client, path: str) -> tuple[dict, dict]:
    wall = time.perf_counter()
    cpu = _cpu_seconds()
    response = client.get(path)
    metric = {
        "wall_seconds": time.perf_counter() - wall,
        "cpu_seconds": _cpu_seconds() - cpu,
        "response_bytes": len(response.content),
    }
    if response.status_code != 200:
        raise AssertionError(f"{path} returned HTTP {response.status_code}: {response.text[:300]}")
    if not response.headers.get("content-type", "").startswith("application/json"):
        raise AssertionError(f"{path} did not return JSON")
    return response.json(), metric


def address_digest(addresses: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(addresses, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _common_signature(current: dict, hunt: dict, topology: dict, reach: dict) -> dict:
    current_addresses = [str(item.get("ip") or "") for item in current.get("hosts") or []]
    return {
        "current": {
            "status": current.get("status"), "host_count": current.get("host_count"),
            "hosts": len(current.get("hosts") or []),
            "scan_count": (current.get("source") or {}).get("scan_count"),
            "unique_host_addresses": len(set(current_addresses)),
            "ordered_host_addresses_sha256": address_digest(current_addresses),
        },
        "hunt": {
            "status": hunt.get("status"), "host_count": hunt.get("host_count"),
            "finding_count": hunt.get("finding_count"),
        },
        "map": topology.get("summary") or {},
        "reach": {
            "hosts": len(reach.get("hosts") or []),
            "devices": len(reach.get("devices") or []),
            "saved_networks": len(reach.get("saved_networks") or []),
        },
    }


def run_once(
    target_root: Path, corpus_root: Path, data_root: Path,
    git_attestation: dict, image_attestation: dict, repeat: int,
    foundation: bool,
) -> dict:
    if data_root.exists() or data_root.is_symlink():
        raise ValueError("Data directory must not exist before a benchmark repeat")
    manifest, manifest_sha, corpus_bytes = _verify_corpus(corpus_root)
    source_sha, source_files = _source_digest(target_root)
    revision, image_id, identity = _validate_attestations(git_attestation, image_attestation, source_sha)
    data_root.mkdir(parents=True)
    os.environ["ANALYZER_DATA_DIR"] = str(data_root)
    os.environ["NCT_AUTH_MODE"] = "disabled"
    sys.path.insert(0, str(target_root))
    from fastapi.testclient import TestClient
    import app.database as database
    import app.main as main
    import app.poc as poc

    # Enter lifespan once to create the target revision's complete schema, while
    # replacing background execution with an inert wait so it cannot affect timing.
    main.start_derived_job_worker = lambda *_args, **_kwargs: None
    main.recover_scheduler_state = lambda: None
    main.schedule_worker = lambda stop: stop.wait()
    client = TestClient(main.app)
    client.__enter__()
    staged = _stage_common(manifest, corpus_root, data_root, poc, database)
    if foundation:
        main.reconcile_device_evidence_catalog(staged["db_path"], data_root / "device-configs")
    processed = _stage_foundation(corpus_root, staged["db_path"]) if foundation else None
    db_before = _database_state(staged["db_path"])
    evidence_before = _evidence_digest(data_root)
    total_wall, total_cpu = time.perf_counter(), _cpu_seconds()
    metrics = {}
    try:
        current, metrics["current:first"] = _request(client, "/api/analysis/network")
        current_repeat, metrics["current:repeat"] = _request(client, "/api/analysis/network")
        hunt, metrics["hunt:shared-reuse"] = _request(client, "/api/hunting/network")
        topology, metrics["map:shared-reuse"] = _request(client, "/api/network-map")
        reach, metrics["reach:shared-reuse"] = _request(client, "/api/reachability/context")
        if _common_signature(current, hunt, topology, reach) != _common_signature(
            current_repeat, hunt, topology, reach
        ):
            raise AssertionError("Repeated Current Network response changed")
        foundation_result = None
        if foundation:
            revision_token = current.get("source_revision")
            if not revision_token:
                raise AssertionError("Current Network did not return a source revision")
            inventory_subnet = "10.20.0.0/24"
            encoded_subnet = "10.20.0.0%2F24"
            expected_addresses = [f"10.20.0.{index}" for index in range(1, 121)]
            expected_processed_addresses = sorted(expected_addresses)
            first, metrics["current-page:first"] = _request(
                client,
                f"/api/analysis/network/page?limit=100&offset=0&subnet={encoded_subnet}"
                f"&revision={revision_token}",
            )
            total = first["pagination"]["total"]
            last_offset = ((total - 1) // 100) * 100 if total else 0
            last, metrics["current-page:last"] = _request(
                client,
                f"/api/analysis/network/page?limit=100&offset={last_offset}&subnet={encoded_subnet}"
                f"&revision={revision_token}",
            )
            ips, metrics["current-ips:complete"] = _request(
                client,
                f"/api/analysis/network/ips?subnet={encoded_subnet}&revision={revision_token}",
            )
            lfa, metrics["current-lfa:complete"] = _request(
                client,
                f"/api/analysis/network/outliers?threshold=20&subnet={encoded_subnet}"
                f"&revision={revision_token}",
            )
            scopes, metrics["processed:scopes"] = _request(client, "/api/foundation-evidence/scopes")
            scope_id = processed["scope_id"]
            scope_first, metrics["processed:first-page"] = _request(
                client, f"/api/foundation-evidence/scopes/{scope_id}?limit=100&offset=0"
            )
            endpoint_total = scope_first["pagination"]["total"]
            processed_last_offset = ((endpoint_total - 1) // 100) * 100 if endpoint_total else 0
            scope_last, metrics["processed:last-page"] = _request(
                client,
                f"/api/foundation-evidence/scopes/{scope_id}?limit=100"
                f"&offset={processed_last_offset}",
            )
            entity_id = scope_first["endpoints"][0]["entity_id"]
            endpoint, metrics["processed:endpoint"] = _request(
                client, f"/api/foundation-evidence/scopes/{scope_id}/endpoints/{entity_id}"
            )
            latest, metrics["processed:latest"] = _request(
                client, f"/api/foundation-evidence/scopes/{scope_id}/endpoints/{entity_id}/latest-observations"
            )
            receipt = endpoint["current_assignment_receipts"][0]
            assignment_id = receipt["assignment"]["assignment_id"]
            assessment_id = receipt["assessment"]["assessment_id"]
            services, metrics["processed:services"] = _request(
                client,
                f"/api/foundation-evidence/scopes/{scope_id}/endpoints/{entity_id}"
                f"/assignments/{assignment_id}/assessments/{assessment_id}/services?limit=100&offset=0",
            )
            current_first_addresses = [item.get("ip") for item in first["hosts"]]
            current_last_addresses = [item.get("ip") for item in last["hosts"]]
            exported_addresses = list(ips.get("ips") or [])
            processed_first_addresses = [item.get("address") for item in scope_first["endpoints"]]
            processed_last_addresses = [item.get("address") for item in scope_last["endpoints"]]
            if (
                total != 120
                or first["pagination"].get("offset") != 0
                or last["pagination"].get("offset") != 100
                or current_first_addresses != expected_addresses[:100]
                or current_last_addresses != expected_addresses[100:]
                or set(current_first_addresses).intersection(current_last_addresses)
            ):
                raise AssertionError("Filtered Current Network page/order oracle mismatch")
            if exported_addresses != expected_addresses or ips.get("count") != 120:
                raise AssertionError("Complete IP export does not match the current inventory")
            lfa_member_count = sum(
                item.get("member_count", 0) for item in lfa.get("groups") or []
            )
            if lfa.get("subnet") != inventory_subnet or lfa_member_count != 120:
                raise AssertionError("Filtered LFA scope/member oracle mismatch")
            if (
                endpoint_total != 120
                or scope_first["pagination"].get("offset") != 0
                or scope_last["pagination"].get("offset") != 100
                or processed_first_addresses != expected_processed_addresses[:100]
                or processed_last_addresses != expected_processed_addresses[100:]
                or set(processed_first_addresses).intersection(processed_last_addresses)
            ):
                raise AssertionError("Processed Evidence paging oracle mismatch")
            if scopes["pagination"]["total"] != 1 or latest.get("contract") != "latest-supported-nmap-observations:1":
                raise AssertionError("Processed Evidence catalog/latest oracle mismatch")
            if services["pagination"]["total"] < 1:
                raise AssertionError("Processed Evidence service receipt is empty")
            foundation_result = {
                "inventory_subnet": inventory_subnet,
                "current_filtered_total": total,
                "current_first_count": len(current_first_addresses),
                "current_last_count": len(current_last_addresses),
                "current_ordered_addresses_sha256": address_digest(
                    current_first_addresses + current_last_addresses
                ),
                "current_page_overlap_count": len(
                    set(current_first_addresses).intersection(current_last_addresses)
                ),
                "export_count": ips["count"],
                "export_addresses_sha256": address_digest(exported_addresses),
                "lfa_member_count": lfa_member_count,
                "processed_scope_count": scopes["pagination"]["total"],
                "processed_endpoint_total": endpoint_total,
                "processed_first_count": len(scope_first["endpoints"]),
                "processed_last_count": len(scope_last["endpoints"]),
                "processed_ordered_addresses_sha256": address_digest(
                    processed_first_addresses + processed_last_addresses
                ),
                "processed_page_overlap_count": len(
                    set(processed_first_addresses).intersection(processed_last_addresses)
                ),
                "latest_contract": latest["contract"],
                "service_total": services["pagination"]["total"],
            }
    finally:
        client.__exit__(None, None, None)

    db_after = _database_state(staged["db_path"])
    evidence_after = _evidence_digest(data_root)
    changed_tables = sorted({
        *[name for name, value in db_before["table_digests"].items()
          if db_after["table_digests"].get(name) != value],
        *[name for name in db_after["table_digests"] if name not in db_before["table_digests"]],
    })
    allowed_changes = [] if foundation else [
        "device_analysis_cache", "device_collections", "scan_analysis_cache",
    ]
    if changed_tables != allowed_changes or evidence_before != evidence_after:
        raise AssertionError(
            "Read-only HTTP workloads changed retained state: "
            f"tables={changed_tables}, allowed={allowed_changes}, "
            f"evidence_changed={evidence_before != evidence_after}"
        )
    names = expected_workloads(foundation)
    if sorted(metrics) != names:
        raise AssertionError("HTTP benchmark did not execute the fixed capability matrix")
    retained = _retained_state(data_root)
    peak, peak_method, peak_detail = _peak_memory()
    total = {
        "wall_seconds": time.perf_counter() - total_wall,
        "cpu_seconds": _cpu_seconds() - total_cpu,
        "peak_rss_bytes": peak,
        "peak_rss_method": peak_method,
        **peak_detail,
    }
    failures = []
    for name, metric in metrics.items():
        limit = ABSOLUTE_LIMITS[
            "foundation_request_wall_seconds" if name in FOUNDATION_WORKLOADS
            else "common_request_wall_seconds"
        ]
        if metric["wall_seconds"] > limit:
            failures.append(f"{name} wall limit exceeded")
        size_limit = ABSOLUTE_LIMITS[
            "complete_response_bytes" if name in {
                "current:first", "current:repeat", "hunt:shared-reuse",
                "map:shared-reuse", "reach:shared-reuse", "current-ips:complete",
                "current-lfa:complete",
            } else "bounded_response_bytes"
        ]
        if metric["response_bytes"] > size_limit:
            failures.append(f"{name} response-size limit exceeded")
    for key in ("wall_seconds", "cpu_seconds"):
        if total[key] > ABSOLUTE_LIMITS[f"whole_run_{key}"]:
            failures.append(f"whole-run {key} limit exceeded")
    if peak > ABSOLUTE_LIMITS["whole_run_peak_rss_bytes"]:
        failures.append("whole-run peak memory limit exceeded")
    if retained["data_root_bytes"] > ABSOLUTE_LIMITS["retained_data_root_bytes"]:
        failures.append("retained data-root size limit exceeded")
    return {
        "benchmark": "phase0-http-persistent-view-comparison",
        "runner_version": RUNNER_VERSION,
        "runner_sha256": _sha256(Path(__file__).read_bytes()),
        "comparison_statistic": COMPARISON_STATISTIC,
        "repeat": repeat,
        "foundation_capabilities": foundation,
        "target": {
            "revision": revision, "source_digest_sha256": source_sha,
            "source_file_count": source_files, "container_image_id": image_id,
            "identity_evidence": identity,
        },
        "corpus": {
            "manifest_sha256": manifest_sha,
            "generator_version": manifest["generator_version"],
            "file_count": len(manifest["files"]), "total_bytes": corpus_bytes,
        },
        "request_session": {
            "kind": "one fixed ordered in-process TestClient session",
            "order": request_order(foundation),
            "background_work_disabled_before_measurement": True,
            "staging_complete_before_measurement": True,
        },
        "expected_workloads": names,
        "metrics": metrics,
        "correctness": {
            "staged": {
                "nmap_files": staged["nmap_files"],
                "device_files": staged["device_files"],
            },
            "common": _common_signature(current, hunt, topology, reach),
            "foundation": foundation_result,
            "database_logical_sha256_before": db_before["logical_sha256"],
            "database_logical_sha256_after": db_after["logical_sha256"],
            "database_logical_state_unchanged": not changed_tables,
            "database_main_file_before": db_before["main_file_sha256"],
            "database_main_file_after": db_after["main_file_sha256"],
            "database_table_counts": db_before["table_counts"],
            "database_tables_changed_by_requests": changed_tables,
            "allowed_database_table_changes": allowed_changes,
            "evidence_sha256_unchanged": evidence_before,
        },
        "retained_state": retained,
        "total": total,
        "limits": {"absolute": ABSOLUTE_LIMITS, "relative": RELATIVE_LIMITS},
        "failures": failures,
        "passed": not failures,
        "limitations": [
            "In-process TestClient HTTP measurements only.",
            "One fixed ordered session measures first build and shared reuse; later requests are not independent cold starts.",
            "Rendered browser, multi-process, Range, mission, production-history and physical-hardware performance are not measured.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--git-attestation", type=Path, required=True)
    parser.add_argument("--image-attestation", type=Path, required=True)
    parser.add_argument("--repeat", type=int, required=True)
    parser.add_argument("--foundation-capabilities", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_once(
        args.target_root.resolve(), args.corpus, args.data_root,
        json.loads(args.git_attestation.read_text(encoding="utf-8")),
        json.loads(args.image_attestation.read_text(encoding="utf-8")),
        args.repeat, args.foundation_capabilities,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
