from __future__ import annotations

import sqlite3
import threading
import ipaddress
import json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path


SQLITE_BUSY_TIMEOUT_MS = 30_000


def initialize_once_per_database(initialize):
    """Run a module's schema setup once per database file in this process.

    A failed setup is retried. Replacing the database file invalidates the cache;
    in-place restores or schema changes require an application restart.
    """
    ready = {}
    lock = threading.RLock()

    def identity(path):
        try:
            info = path.stat()
            return info.st_dev, info.st_ino
        except FileNotFoundError:
            return None

    @wraps(initialize)
    def ensure(db_path: Path):
        path = Path(db_path).resolve()
        current = identity(path)
        if current is not None and ready.get(path) == current:
            return
        with lock:
            current = identity(path)
            if current is not None and ready.get(path) == current:
                return
            initialize(path)
            current = identity(path)
            if current is not None:
                ready[path] = current
    return ensure


class DatabaseConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect_database(db_path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    """Open an application connection with consistent lock handling."""
    connection = sqlite3.connect(
        db_path.resolve().as_uri() + "?mode=ro" if read_only else db_path,
        uri=read_only,
        timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
        factory=DatabaseConnection,
    )
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.create_function(
        "nct_normalize_ipv4_network_list",
        1,
        _normalize_ipv4_network_list_json,
        deterministic=True,
    )
    connection.create_function(
        "nct_is_canonical_utc",
        1,
        _is_canonical_utc,
        deterministic=True,
    )
    return connection


def _normalize_ipv4_network_list_json(value: str) -> str | None:
    """Return canonical JSON for a valid IPv4 network list, or NULL when invalid."""
    try:
        parsed = json.loads(value)
        if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
            return None
        networks = [ipaddress.ip_network(item.strip(), strict=False) for item in parsed]
        if any(network.version != 4 for network in networks):
            return None
        normalized = [str(network) for network in ipaddress.collapse_addresses(networks)]
        return json.dumps(normalized)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _is_canonical_utc(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return 0
    canonical = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    return int(parsed.microsecond == 0 and value == canonical)


def configure_database(db_path: Path) -> None:
    """Apply persistent concurrency settings before request handling begins."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect_database(db_path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
