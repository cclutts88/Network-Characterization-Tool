#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.scan_work_recovery import (
    ScanWorkRecoveryError,
    apply_scan_work_recovery,
    diagnose_scan_work,
    recovery_pause,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preview or apply the stopped-container NCT scan-work recovery plan."
    )
    parser.add_argument("--data-dir", type=Path, default=Path("/data"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-digest")
    parser.add_argument("--actor")
    parser.add_argument("--backup-path")
    parser.add_argument("--backup-sha256")
    args = parser.parse_args()

    db_path = args.data_dir / "analyzer.db"
    pause = recovery_pause(args.data_dir)
    if args.apply:
        required = {
            "--plan-digest": args.plan_digest,
            "--actor": args.actor,
            "--backup-path": args.backup_path,
            "--backup-sha256": args.backup_sha256,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            parser.error("Apply requires " + ", ".join(missing))
        if pause and pause.get("state") == "review_required":
            parser.exit(
                2,
                "Recovery refused: the previous recovery is waiting for administrator review\n",
            )
        if pause and pause.get("state") == "invalid":
            parser.exit(2, "Recovery refused: the saved recovery pause is invalid\n")
        if pause and pause.get("state") == "diagnosis_required" and pause.get("recovery_id"):
            parser.exit(
                2,
                "Recovery refused: an earlier apply reached a fail-closed recovery state; "
                "preserve the backup and inspect the database receipt\n",
            )
        try:
            result = apply_scan_work_recovery(
                db_path,
                args.data_dir,
                expected_plan_digest=args.plan_digest,
                actor=args.actor,
                backup_path=args.backup_path,
                backup_sha256=args.backup_sha256,
            )
        except ScanWorkRecoveryError as exc:
            parser.exit(2, f"Recovery refused: {exc}\n")
    else:
        result = diagnose_scan_work(db_path)
        result["pause"] = pause
        if pause and (
            pause.get("state") in {"review_required", "invalid"}
            or pause.get("state") == "diagnosis_required" and pause.get("recovery_id")
        ):
            result["safe_to_apply"] = False
            result["blockers"] = [
                *list(result.get("blockers") or []),
                (
                    "The previous recovery is waiting for administrator review"
                    if pause.get("state") == "review_required"
                    else (
                        "The saved recovery pause record is invalid"
                        if pause.get("state") == "invalid"
                        else "An earlier apply is incomplete; preserve the backup and inspect the database receipt"
                    )
                ),
            ]

    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
        try:
            args.output.chmod(0o600)
        except PermissionError:
            # FAT/NTFS transfer media can reject POSIX mode changes. The host
            # wrapper still creates a private recovery directory where the
            # filesystem supports it and never treats chmod as verification.
            pass
    else:
        print(payload, end="")
    return 0 if result.get("safe_to_apply", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
