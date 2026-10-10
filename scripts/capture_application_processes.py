#!/usr/bin/env python3
"""Identify Uvicorn application processes inside the benchmark container."""
from __future__ import annotations

import json
from pathlib import Path


def capture() -> dict:
    processes = []
    for directory in sorted(Path("/proc").iterdir(), key=lambda path: path.name):
        if not directory.name.isdigit():
            continue
        try:
            command = (directory / "cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
        except (OSError, UnicodeDecodeError):
            continue
        if "uvicorn" in command and "app.main:app" in command:
            processes.append({"pid": int(directory.name), "command": command})
    return {"uvicorn_application_process_count": len(processes), "processes": processes}


if __name__ == "__main__":
    print(json.dumps(capture(), sort_keys=True))
