#!/usr/bin/env python3
"""Eight-client, single-worker NCT concurrency benchmark."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.cookiejar
import json
import math
import multiprocessing as mp
from pathlib import Path
import queue
import resource
import time
import urllib.error
import urllib.request


BENCHMARK_VERSION = "phase0-concurrent-clients:1"
WORKER_COUNT = 8
CYCLES = 4
REQUEST_TIMEOUT_SECONDS = 60
TOTAL_WALL_LIMIT_SECONDS = 240
READ_P95_LIMIT_SECONDS = 30
WRITE_P95_LIMIT_SECONDS = 10
MAX_RESPONSE_BYTES = {
    "current": 4 * 1024 * 1024,
    "hunt": 64 * 1024 * 1024,
    "map": 32 * 1024 * 1024,
    "reach": 32 * 1024 * 1024,
    "workspace": 2 * 1024 * 1024,
    "write": 2 * 1024 * 1024,
}
EXPECTED = {
    "current_total": 4188,
    "hunt_hosts": 4188,
    "hunt_findings": 6125,
    "map_interfaces": 1000,
    "map_relationships": 1041,
    "reach_hosts": 4188,
    "reach_devices": 0,
}
EXPECTED_MAP_SUMMARY = {
    "devices": 1, "gateways": 0, "interfaces": 1000, "subnets": 0,
    "hosts": 4188, "relationships": 1041, "nmap_records_read": 4315,
    "configuration_records_read": 4, "mac_observations": 4315,
    "mac_identified_hosts": 4188, "mac_conflicts": 0, "arp_neighbors": 0,
    "topology_neighbors": 0, "switchport_links": 0,
}
EXPECTED_ORDERED_HOSTS_SHA256 = "09dcf4ae04213b940e824b8aeaf73ac0b71db509f46dd3fef26d7e558e2325b1"
REQUEST_ORDER = [
    "current", "hunt", "map", "reach", "workspace:notes", "workspace:layouts",
    "workspace:view", "workspace:presets", "write:note", "write:layout",
    "write:view", "write:preset",
]


def _cgroup_resources() -> dict:
    result: dict[str, int | str | None] = {
        "source": "linux-cgroup-v2",
        "cpu_usage_usec": None,
        "peak_memory_bytes": None,
    }
    try:
        for line in Path("/sys/fs/cgroup/cpu.stat").read_text(encoding="utf-8").splitlines():
            key, value = line.split(None, 1)
            if key == "usage_usec":
                result["cpu_usage_usec"] = int(value)
        peak = Path("/sys/fs/cgroup/memory.peak")
        if peak.is_file():
            result["peak_memory_bytes"] = int(peak.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        result["source"] = "unavailable"
    return result


def _password(username: str) -> str:
    return f"phase0 {username} password"


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _latency(values: list[float]) -> dict:
    return {
        "count": len(values),
        "p50_seconds": round(_percentile(values, 0.50), 6),
        "p95_seconds": round(_percentile(values, 0.95), 6),
        "max_seconds": round(max(values, default=0.0), 6),
    }


def _address_digest(addresses: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(addresses, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass
class HttpResult:
    status: int
    body: bytes
    started_ns: int
    ended_ns: int


class Session:
    def __init__(self, base_url: str):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, payload: dict | None = None) -> HttpResult:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        started = time.monotonic_ns()
        try:
            with self.opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                content = response.read()
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            content = exc.read()
            status = int(exc.code)
        ended = time.monotonic_ns()
        return HttpResult(status, content, started, ended)


def _json(result: HttpResult, *, expected_status: int, label: str) -> dict:
    if result.status != expected_status:
        detail = result.body[:500].decode("utf-8", "replace")
        raise AssertionError(f"{label} returned HTTP {result.status}: {detail}")
    try:
        value = json.loads(result.body)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{label} returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise AssertionError(f"{label} did not return a JSON object")
    return value


def _login(session: Session, username: str) -> None:
    result = session.request(
        "POST", "/api/auth/login", {"username": username, "password": _password(username)}
    )
    data = _json(result, expected_status=200, label=f"login:{username}")
    if (data.get("analyst") or {}).get("username") != username:
        raise AssertionError(f"login:{username} returned the wrong identity")


def setup(base_url: str) -> dict:
    admin = Session(base_url)
    _login(admin, "phase0admin")
    users = [f"analyst-{index:02d}" for index in range(WORKER_COUNT)]
    for username in users + ["collision-analyst"]:
        result = admin.request(
            "POST",
            "/api/auth/users",
            {
                "username": username,
                "display_name": username.replace("-", " ").title(),
                "role": "analyst",
                "password": _password(username),
            },
        )
        _json(result, expected_status=200, label=f"create-user:{username}")

    records: dict[str, dict] = {}
    for index, username in enumerate(users):
        session = Session(base_url)
        _login(session, username)
        note = _json(
            session.request(
                "POST", "/api/workspaces/notes",
                {"title": "Concurrency note", "kind": "note", "content": "setup"},
            ), expected_status=200, label=f"setup-note:{username}",
        )
        layout = _json(
            session.request(
                "POST", "/api/workspaces/layouts",
                {"name": "Concurrency layout", "snapshot": {"marker": "setup", "index": index}},
            ), expected_status=200, label=f"setup-layout:{username}",
        )
        view = _json(
            session.request(
                "PUT", "/api/workspaces/views/hunt",
                {"snapshot": {"marker": "setup", "index": index}, "expected_version": None},
            ), expected_status=200, label=f"setup-view:{username}",
        )
        preset = _json(
            session.request(
                "POST", "/api/workspaces/views/analyze/presets",
                {"name": "Concurrency preset", "snapshot": {"marker": "setup", "index": index}},
            ), expected_status=200, label=f"setup-preset:{username}",
        )
        records[username] = {
            "note_id": note["note_id"],
            "layout_id": layout["layout_id"],
            "preset_id": preset["preset_id"],
            "versions": {
                "note": note["version"], "layout": layout["version"],
                "view": view["version"], "preset": preset["version"],
            },
        }

    collision_session = Session(base_url)
    _login(collision_session, "collision-analyst")
    collision = _json(
        collision_session.request(
            "POST", "/api/workspaces/notes",
            {"title": "Collision note", "kind": "note", "content": "setup"},
        ), expected_status=200, label="setup-collision-note",
    )
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "users": users,
        "records": records,
        "collision": {"note_id": collision["note_id"], "version": collision["version"]},
    }


def _record(
    records: list[dict], result: HttpResult, family: str, kind: str, expected_status: int = 200
) -> dict:
    data = _json(result, expected_status=expected_status, label=family)
    bound_family = family.split(":", 1)[0]
    limit = MAX_RESPONSE_BYTES.get(bound_family, MAX_RESPONSE_BYTES["write"])
    if len(result.body) > limit:
        raise AssertionError(f"{family} response exceeded {limit} bytes")
    records.append(
        {
            "family": family,
            "kind": kind,
            "status": result.status,
            "bytes": len(result.body),
            "started_ns": result.started_ns,
            "ended_ns": result.ended_ns,
            "latency_seconds": (result.ended_ns - result.started_ns) / 1_000_000_000,
        }
    )
    return data


def _worker(
    base_url: str, index: int, setup_data: dict, barrier, output
) -> None:
    username = setup_data["users"][index]
    own = setup_data["records"][username]
    records: list[dict] = []
    started = time.monotonic_ns()
    usage_start = resource.getrusage(resource.RUSAGE_SELF)
    error = None
    try:
        session = Session(base_url)
        _login(session, username)
        barrier.wait(timeout=30)
        versions = dict(own["versions"])
        for cycle in range(1, CYCLES + 1):
            offset = ((index + cycle - 1) % 4) * 25
            expected_page = [f"10.20.0.{value}" for value in range(offset + 1, offset + 26)]
            current = _record(
                records,
                session.request(
                    "GET",
                    f"/api/analysis/network/page?limit=25&offset={offset}&subnet=10.20.0.0%2F24",
                ),
                "current", "read",
            )
            if current.get("status") != "analysis_network_page_complete":
                raise AssertionError("Current Network returned the wrong status")
            if (current.get("pagination") or {}).get("total") != 120:
                raise AssertionError("Current Network returned the wrong total")
            current_addresses = [str(item.get("ip") or "") for item in current.get("hosts") or []]
            if current_addresses != expected_page:
                raise AssertionError("Current Network returned the wrong exact page order")
            records[-1]["correctness"] = {"offset": offset, "addresses": current_addresses, "total": 120}

            hunt = _record(
                records, session.request("GET", "/api/hunting/network"), "hunt", "read"
            )
            if hunt.get("host_count") != EXPECTED["hunt_hosts"] or hunt.get("finding_count") != EXPECTED["hunt_findings"]:
                raise AssertionError("Hunt returned the wrong host or finding total")
            hunt_addresses = [str(item.get("ip") or "") for item in hunt.get("hosts") or []]
            if len(hunt_addresses) != EXPECTED["hunt_hosts"] or _address_digest(hunt_addresses) != EXPECTED_ORDERED_HOSTS_SHA256:
                raise AssertionError("Hunt returned the wrong complete host order")
            records[-1]["correctness"] = {
                "hosts": hunt.get("host_count"), "findings": hunt.get("finding_count"),
                "ordered_hosts_sha256": _address_digest(hunt_addresses),
            }

            topology = _record(
                records, session.request("GET", "/api/network-map"), "map", "read"
            )
            summary = topology.get("summary") or {}
            if summary != EXPECTED_MAP_SUMMARY:
                raise AssertionError("Map returned the wrong topology totals")
            records[-1]["correctness"] = summary

            reach = _record(
                records, session.request("GET", "/api/reachability/context"), "reach", "read"
            )
            reach_record = {
                "hosts": len(reach.get("hosts") or []),
                "devices": len(reach.get("devices") or []),
                "saved_networks": len(reach.get("saved_networks") or []),
                "device_collections": int(reach.get("device_collections") or 0),
            }
            if reach_record != {"hosts": 4188, "devices": 0, "saved_networks": 0, "device_collections": 0}:
                raise AssertionError("Reach returned the wrong evidence totals")
            records[-1]["correctness"] = reach_record

            notes = _record(
                records, session.request("GET", "/api/workspaces/notes?page=hunt"),
                "workspace:notes", "read",
            )
            if [item.get("note_id") for item in notes.get("notes") or []] != [own["note_id"]]:
                raise AssertionError("Personal notes exposed missing or cross-owner state")
            records[-1]["correctness"] = {"note_ids": [own["note_id"]], "owners": [username]}
            layouts = _record(
                records, session.request("GET", "/api/workspaces/layouts"),
                "workspace:layouts", "read",
            )
            if any(item.get("owner") != username for item in layouts.get("layouts") or []):
                raise AssertionError("Personal layouts exposed a cross-owner record")
            own_layouts = [item for item in layouts.get("layouts") or [] if item.get("owner") == username]
            if [item.get("layout_id") for item in own_layouts] != [own["layout_id"]]:
                raise AssertionError("Personal layouts exposed missing or cross-owner state")
            records[-1]["correctness"] = {"layout_ids": [own["layout_id"]], "owners": [username]}
            view_workspace = _record(
                records, session.request("GET", "/api/workspaces/views/hunt"),
                "workspace:view", "read",
            )
            if (view_workspace.get("preference") or {}).get("owner") != username:
                raise AssertionError("Personal view returned the wrong owner")
            records[-1]["correctness"] = {"owner": username, "version": versions["view"]}
            presets_workspace = _record(
                records, session.request("GET", "/api/workspaces/views/analyze"),
                "workspace:presets", "read",
            )
            presets = presets_workspace.get("presets") or []
            if (
                [item.get("preset_id") for item in presets] != [own["preset_id"]]
                or any(item.get("owner") != username for item in presets)
            ):
                raise AssertionError("Personal presets exposed missing or cross-owner state")
            records[-1]["correctness"] = {"preset_ids": [own["preset_id"]], "owners": [username]}

            marker = f"{username}:{cycle}"
            note = _record(
                records,
                session.request(
                    "POST", "/api/workspaces/notes",
                    {
                        "title": "Concurrency note", "kind": "note", "content": marker,
                        "note_id": own["note_id"], "expected_version": versions["note"],
                    },
                ), "write:note", "write",
            )
            versions["note"] = note["version"]
            records[-1]["correctness"] = {"owner": username, "version": note["version"], "marker": note["content"]}
            layout = _record(
                records,
                session.request(
                    "POST", "/api/workspaces/layouts",
                    {
                        "name": "Concurrency layout", "snapshot": {"marker": marker, "index": index},
                        "layout_id": own["layout_id"], "expected_version": versions["layout"],
                    },
                ), "write:layout", "write",
            )
            versions["layout"] = layout["version"]
            records[-1]["correctness"] = {"owner": username, "version": layout["version"], "marker": (layout.get("snapshot") or {}).get("marker")}
            view = _record(
                records,
                session.request(
                    "PUT", "/api/workspaces/views/hunt",
                    {"snapshot": {"marker": marker, "index": index}, "expected_version": versions["view"]},
                ), "write:view", "write",
            )
            versions["view"] = view["version"]
            records[-1]["correctness"] = {"owner": username, "version": view["version"], "marker": (view.get("snapshot") or {}).get("marker")}
            preset = _record(
                records,
                session.request(
                    "POST", "/api/workspaces/views/analyze/presets",
                    {
                        "name": "Concurrency preset", "snapshot": {"marker": marker, "index": index},
                        "preset_id": own["preset_id"], "expected_version": versions["preset"],
                    },
                ), "write:preset", "write",
            )
            versions["preset"] = preset["version"]
            records[-1]["correctness"] = {"owner": username, "version": preset["version"], "marker": (preset.get("snapshot") or {}).get("marker")}
        neighbor = setup_data["users"][(index + 1) % WORKER_COUNT]
        neighbor_layout = setup_data["records"][neighbor]
        isolation = _record(
            records,
            session.request(
                "POST", "/api/workspaces/layouts",
                {
                    "name": "Cross-owner attempt", "snapshot": {"marker": username},
                    "layout_id": neighbor_layout["layout_id"],
                    "expected_version": 1 + CYCLES,
                },
            ),
            "isolation:layout", "isolation", expected_status=404,
        )
        if "not found" not in str(isolation.get("detail") or "").lower():
            raise AssertionError("Cross-owner mutation did not return the expected denial")
        records[-1]["correctness"] = {"detail": isolation.get("detail"), "neighbor": neighbor}
    except Exception as exc:  # captured in the raw report instead of losing a worker failure
        error = f"{type(exc).__name__}: {exc}"
    usage = resource.getrusage(resource.RUSAGE_SELF)
    output.put(
        {
            "index": index,
            "username": username,
            "pid": mp.current_process().pid,
            "started_ns": started,
            "ended_ns": time.monotonic_ns(),
            "cpu_seconds": round(
                (usage.ru_utime + usage.ru_stime) - (usage_start.ru_utime + usage_start.ru_stime), 6
            ),
            "peak_memory_bytes": int(usage.ru_maxrss) * 1024,
            "records": records,
            "error": error,
        }
    )


def _collision_worker(base_url: str, setup_data: dict, marker: str, barrier, output) -> None:
    session = Session(base_url)
    _login(session, "collision-analyst")
    barrier.wait(timeout=30)
    note = setup_data["collision"]
    result = session.request(
        "POST", "/api/workspaces/notes",
        {
            "title": "Collision note", "kind": "note", "content": marker,
            "note_id": note["note_id"], "expected_version": note["version"],
        },
    )
    detail = result.body[:500].decode("utf-8", "replace")
    try:
        parsed = json.loads(result.body)
    except json.JSONDecodeError:
        parsed = None
    output.put(
        {
            "pid": mp.current_process().pid,
            "marker": marker,
            "status": result.status,
            "body": detail,
            "parsed": parsed,
            "bytes": len(result.body),
            "latency_seconds": (result.ended_ns - result.started_ns) / 1_000_000_000,
            "started_ns": result.started_ns,
            "ended_ns": result.ended_ns,
        }
    )


def _collect(output, count: int) -> list[dict]:
    values = []
    for _ in range(count):
        try:
            values.append(output.get(timeout=TOTAL_WALL_LIMIT_SECONDS))
        except queue.Empty as exc:
            raise AssertionError("A client process did not return a result") from exc
    return values


def validate_run(workers: list[dict], collisions: list[dict], wall_seconds: float) -> dict:
    failures: list[str] = []
    if len(workers) != WORKER_COUNT:
        failures.append(f"expected {WORKER_COUNT} workers, found {len(workers)}")
    if len({item.get("pid") for item in workers}) != WORKER_COUNT:
        failures.append("primary client process IDs are not unique")
    for item in workers:
        if item.get("error"):
            failures.append(f"{item.get('username')}: {item['error']}")
        if len(item.get("records") or []) != CYCLES * len(REQUEST_ORDER) + 1:
            failures.append(f"{item.get('username')}: request count is not fixed")
    collision_statuses = sorted(item.get("status") for item in collisions)
    if collision_statuses != [200, 409]:
        failures.append(f"collision expected [200, 409], found {collision_statuses}")
    if any(
        item.get("bytes", MAX_RESPONSE_BYTES["write"] + 1) > MAX_RESPONSE_BYTES["write"]
        or item.get("latency_seconds", REQUEST_TIMEOUT_SECONDS + 1) > REQUEST_TIMEOUT_SECONDS
        for item in collisions
    ):
        failures.append("collision response size or latency limit exceeded")
    conflict = next((item for item in collisions if item.get("status") == 409), None)
    success = next((item for item in collisions if item.get("status") == 200), None)
    if (
        success
        and (
            not isinstance(success.get("parsed"), dict)
            or success["parsed"].get("version") != 2
            or success["parsed"].get("content") != success.get("marker")
        )
    ):
        failures.append("collision success response did not return version 2 and the winning marker")
    if (
        conflict
        and (
            not isinstance(conflict.get("parsed"), dict)
            or "changed" not in str(conflict["parsed"].get("detail") or "").lower()
        )
    ):
        failures.append("collision conflict response did not explain the stale version")

    all_records = [record for item in workers for record in item.get("records") or []]
    reads = [record for record in all_records if record.get("kind") == "read"]
    writes = [record for record in all_records if record.get("kind") == "write"]
    read_values = [float(record["latency_seconds"]) for record in reads]
    write_values = [float(record["latency_seconds"]) for record in writes]
    if wall_seconds > TOTAL_WALL_LIMIT_SECONDS:
        failures.append("total wall-time limit exceeded")
    if _percentile(read_values, 0.95) > READ_P95_LIMIT_SECONDS:
        failures.append("read p95 latency limit exceeded")
    if _percentile(write_values, 0.95) > WRITE_P95_LIMIT_SECONDS:
        failures.append("write p95 latency limit exceeded")
    overlap = 0
    if writes:
        overlap = sum(
            any(
                read["started_ns"] <= write["ended_ns"]
                and read["ended_ns"] >= write["started_ns"]
                for write in writes
            )
            for read in reads
        )
    if overlap < WORKER_COUNT:
        failures.append("fewer than eight reads completed while writes overlapped")
    family_latency = {
        family: _latency([float(record["latency_seconds"]) for record in all_records if record.get("family") == family])
        for family in sorted({str(record.get("family")) for record in all_records})
    }
    return {
        "passed": not failures,
        "failures": failures,
        "client_processes": WORKER_COUNT,
        "collision_processes": len(collisions),
        "cycles_per_client": CYCLES,
        "requests": len(all_records) + len(collisions),
        "successful_reads_overlapping_write_window": overlap,
        "wall_seconds": round(wall_seconds, 6),
        "throughput_requests_per_second": round(
            (len(all_records) + len(collisions)) / wall_seconds, 3
        ) if wall_seconds else 0.0,
        "read_latency": _latency(read_values),
        "write_latency": _latency(write_values),
        "family_latency": family_latency,
        "limits": {
            "total_wall_seconds": TOTAL_WALL_LIMIT_SECONDS,
            "read_p95_seconds": READ_P95_LIMIT_SECONDS,
            "write_p95_seconds": WRITE_P95_LIMIT_SECONDS,
            "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
            "response_bytes": MAX_RESPONSE_BYTES,
        },
    }


def run(base_url: str, setup_data: dict) -> dict:
    context = mp.get_context("spawn")
    output = context.Queue()
    barrier = context.Barrier(WORKER_COUNT)
    processes = [
        context.Process(target=_worker, args=(base_url, index, setup_data, barrier, output))
        for index in range(WORKER_COUNT)
    ]
    wall_started = time.perf_counter()
    for process in processes:
        process.start()
    workers = _collect(output, WORKER_COUNT)
    for process in processes:
        process.join(timeout=30)
    worker_exits = [process.exitcode for process in processes]

    collision_output = context.Queue()
    collision_barrier = context.Barrier(2)
    collision_processes = [
        context.Process(
            target=_collision_worker,
            args=(base_url, setup_data, f"collision-{index}", collision_barrier, collision_output),
        )
        for index in range(2)
    ]
    for process in collision_processes:
        process.start()
    collisions = _collect(collision_output, 2)
    for process in collision_processes:
        process.join(timeout=30)
    collision_exits = [process.exitcode for process in collision_processes]
    wall_seconds = time.perf_counter() - wall_started
    summary = validate_run(workers, collisions, wall_seconds)
    if any(code != 0 for code in worker_exits + collision_exits):
        summary["failures"].append("one or more client processes exited unsuccessfully")
        summary["passed"] = False
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "summary": summary,
        "client_container_resources": _cgroup_resources(),
        "worker_exit_codes": worker_exits,
        "collision_exit_codes": collision_exits,
        "workers": sorted(workers, key=lambda item: item["index"]),
        "collisions": sorted(collisions, key=lambda item: item["marker"]),
    }


def self_test() -> dict:
    records = []
    start = 1_000_000_000
    for index in range(WORKER_COUNT):
        worker_records = []
        for cycle in range(CYCLES):
            for position in range(len(REQUEST_ORDER)):
                kind = "read" if position < 8 else "write"
                worker_records.append(
                    {
                        "family": REQUEST_ORDER[position],
                        "kind": kind,
                        "latency_seconds": 0.01,
                        "started_ns": start + position * 1_000_000,
                        "ended_ns": (
                            start + 20_000_000
                            if kind == "read"
                            else start + position * 1_000_000 + 500_000
                        ),
                    }
                )
        worker_records.append(
            {
                "family": "isolation:layout", "kind": "isolation", "status": 404,
                "latency_seconds": 0.01,
                "started_ns": start, "ended_ns": start + 500_000,
            }
        )
        records.append({"username": f"analyst-{index:02d}", "pid": index + 100, "records": worker_records, "error": None})
    result = validate_run(
        records,
            [
                {
                    "status": 200, "body": "ok", "marker": "collision-0",
                    "parsed": {"version": 2, "content": "collision-0"},
                    "bytes": 20, "latency_seconds": 0.01,
                },
                {
                    "status": 409, "body": "The note changed after you opened it",
                    "parsed": {"detail": "The note changed after you opened it"},
                    "bytes": 60, "latency_seconds": 0.01,
                },
            ],
        1.0,
    )
    if not result["passed"]:
        raise AssertionError(result["failures"])
    records[0]["pid"] = records[1]["pid"]
    failed = validate_run(records, [{"status": 200}, {"status": 200}], 999)
    if failed["passed"]:
        raise AssertionError("self-test fault injection did not fail")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("setup", "run", "self-test"), required=True)
    parser.add_argument("--base-url")
    parser.add_argument("--setup", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "self-test":
        result = self_test()
    elif args.mode == "setup":
        if not args.base_url:
            parser.error("--base-url is required")
        result = setup(args.base_url)
    else:
        if not args.base_url or args.setup is None:
            parser.error("--base-url and --setup are required")
        result = run(args.base_url, json.loads(args.setup.read_text(encoding="utf-8")))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
