#!/usr/bin/env python3
"""Read a confirmed Administrator secret from the controlling terminal."""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import signal
import sys
import termios


class SecretEntryInterrupted(Exception):
    pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args()
    if args.attempts < 1 or args.attempts > 10:
        parser.error("attempts must be between 1 and 10")
    if not sys.stdin.isatty():
        raise SystemExit("Administrator password entry requires an interactive terminal.")
    output = args.output.resolve()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.exists():
        raise SystemExit("Refusing to overwrite an existing password handoff file.")

    terminal_fd = sys.stdin.fileno()
    terminal_state = termios.tcgetattr(terminal_fd)
    handled_signals = tuple(
        value for value in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM) if value is not None
    )
    previous_handlers = {value: signal.getsignal(value) for value in handled_signals}

    def interrupt(signum: int, _frame: object) -> None:
        raise SecretEntryInterrupted(f"signal {signum}")

    try:
        for value in handled_signals:
            signal.signal(value, interrupt)
        # A VM paste can leave the Enter key from the launch command waiting in
        # the terminal input queue. Discard it before showing the first secret
        # prompt. Do not flush between the two current prompts.
        termios.tcflush(terminal_fd, termios.TCIFLUSH)
        for attempt in range(1, args.attempts + 1):
            first = getpass.getpass(
                "New password (12-256 characters; spaces and symbols are accepted): "
            )
            second = getpass.getpass("Confirm password: ")
            if first != second:
                first = second = ""
                print(
                    f"Passwords did not match. Try again ({attempt}/{args.attempts}).",
                    file=sys.stderr,
                )
                continue
            length = len(first.encode("utf-8"))
            if not 12 <= length <= 256:
                first = second = ""
                print(
                    f"Password must be 12-256 UTF-8 bytes; received {length}. "
                    f"Try again ({attempt}/{args.attempts}).",
                    file=sys.stderr,
                )
                continue
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, first.encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            first = second = ""
            return 0
    except (SecretEntryInterrupted, KeyboardInterrupt):
        raise SystemExit("Administrator password entry was interrupted; no password was saved.")
    finally:
        termios.tcsetattr(terminal_fd, termios.TCSANOW, terminal_state)
        for value, previous in previous_handlers.items():
            signal.signal(value, previous)
    raise SystemExit("Administrator password was not confirmed after the allowed attempts.")


if __name__ == "__main__":
    raise SystemExit(main())
