#!/usr/bin/env python3
"""Print the current Linux cgroup-v2 CPU and peak-memory counters."""
from __future__ import annotations

import json
from pathlib import Path


def capture() -> dict:
    result = {"source": "linux-cgroup-v2", "cpu_usage_usec": None, "peak_memory_bytes": None}
    for line in Path("/sys/fs/cgroup/cpu.stat").read_text(encoding="utf-8").splitlines():
        key, value = line.split(None, 1)
        if key == "usage_usec":
            result["cpu_usage_usec"] = int(value)
    peak = Path("/sys/fs/cgroup/memory.peak")
    if peak.is_file():
        result["peak_memory_bytes"] = int(peak.read_text(encoding="utf-8").strip())
    return result


if __name__ == "__main__":
    print(json.dumps(capture(), sort_keys=True))
