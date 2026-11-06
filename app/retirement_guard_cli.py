"""Host-facing commands for the independent evidence-retirement guard."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.retirement_guard import (
    check_retirement_guard,
    mark_retirement_restore_hold,
    provision_retirement_guard,
    reconcile_retirement_restore,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    provision = commands.add_parser("provision")
    provision.add_argument("--guard-dir", type=Path, required=True)
    provision.add_argument("--installation-id", required=True)
    provision.add_argument("--data-identity", required=True)

    check = commands.add_parser("check")
    check.add_argument("--db", type=Path, required=True)
    check.add_argument("--data-dir", type=Path, required=True)
    check.add_argument("--guard-dir", type=Path, required=True)
    check.add_argument("--data-identity", required=True)

    hold = commands.add_parser("mark-restore-hold")
    hold.add_argument("--guard-dir", type=Path, required=True)
    hold.add_argument("--data-identity", required=True)
    hold.add_argument("--operation-id", required=True)
    hold.add_argument("--detail", required=True)

    reconcile = commands.add_parser("reconcile-restore")
    reconcile.add_argument("--db", type=Path, required=True)
    reconcile.add_argument("--data-dir", type=Path, required=True)
    reconcile.add_argument("--guard-dir", type=Path, required=True)
    reconcile.add_argument("--data-identity", required=True)
    reconcile.add_argument("--operation-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "provision":
        result = provision_retirement_guard(
            args.guard_dir,
            installation_id=args.installation_id,
            data_identity=args.data_identity,
        )
        print(json.dumps({"state": "provisioned", **result}, sort_keys=True))
        return 0
    if args.command == "check":
        status = check_retirement_guard(
            args.db,
            data_dir=args.data_dir,
            guard_dir=args.guard_dir,
            data_identity=args.data_identity,
        )
    elif args.command == "mark-restore-hold":
        status = mark_retirement_restore_hold(
            args.guard_dir,
            data_identity=args.data_identity,
            operation_id=args.operation_id,
            detail=args.detail,
        )
    else:
        status = reconcile_retirement_restore(
            args.db,
            data_dir=args.data_dir,
            guard_dir=args.guard_dir,
            data_identity=args.data_identity,
            operation_id=args.operation_id,
        )
    print(json.dumps(status.__dict__, sort_keys=True))
    return 0 if status.ready else 2


if __name__ == "__main__":  # pragma: no cover - exercised through main
    raise SystemExit(main())

