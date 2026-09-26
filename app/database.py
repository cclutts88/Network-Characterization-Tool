from __future__ import annotations

import sqlite3
from pathlib import Path


SQLITE_BUSY_TIMEOUT_MS = 30_000


class DatabaseConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect_database(db_path: Path) -> sqlite3.Connection:
    """Open an application connection with consistent lock handling."""
    connection = sqlite3.connect(
        db_path,
        timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
        factory=DatabaseConnection,
    )
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def configure_database(db_path: Path) -> None:
    """Apply persistent concurrency settings before request handling begins."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect_database(db_path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
