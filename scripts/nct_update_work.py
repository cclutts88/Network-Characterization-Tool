#!/usr/bin/env python3
"""Trusted console adapter for the installed image's versioned work-repair API."""
import argparse
import json
from pathlib import Path

from app.scan_work_recovery import apply_scan_work_recovery, diagnose_scan_work, recovery_pause


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preview", "apply"))
    parser.add_argument("--plan-digest")
    parser.add_argument("--actor")
    parser.add_argument("--backup-path")
    parser.add_argument("--backup-sha256")
    args = parser.parse_args()
    root = Path("/data")
    pause = recovery_pause(root)
    if args.mode == "preview":
        value = diagnose_scan_work(root / "analyzer.db")
        if pause and (pause.get("state") in {"review_required", "invalid"} or pause.get("state") == "diagnosis_required" and pause.get("recovery_id")):
            value["safe_to_apply"] = False
            value["blockers"] = [*value.get("blockers", []), "A previous recovery requires administrator review"]
    else:
        if pause and (pause.get("state") in {"review_required", "invalid"} or pause.get("state") == "diagnosis_required" and pause.get("recovery_id")):
            raise ValueError("A previous recovery requires administrator review")
        if not all((args.plan_digest, args.actor, args.backup_path, args.backup_sha256)):
            raise ValueError("Repair requires the reviewed plan, operator and verified backup")
        value = apply_scan_work_recovery(root / "analyzer.db", root,
            expected_plan_digest=args.plan_digest, actor=args.actor,
            backup_path=args.backup_path, backup_sha256=args.backup_sha256)
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
