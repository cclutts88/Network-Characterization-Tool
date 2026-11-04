#!/usr/bin/env python3
"""Refuse fresh-install resume when any analyst or retained evidence exists."""
from __future__ import annotations

import sys
import sqlite3
from pathlib import Path

from nct_fresh_handoff import verify_empty


def main() -> int:
    if len(sys.argv) != 4:
        raise ValueError("usage: nct-verify-empty-fresh-resume.py DATABASE DATA_ROOT ADMIN")
    resets = verify_empty(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    print(f"PASSWORD_RESET_COUNT={resets}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise SystemExit(f"Fresh-install empty-state verification failed: {exc}")
