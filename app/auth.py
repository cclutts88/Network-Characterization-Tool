from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3


SESSION_COOKIE = "nct_session"
PASSWORD_ROUNDS = 600_000
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}")
ROLES = {"admin", "analyst", "viewer"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def auth_enabled() -> bool:
    return os.environ.get("NCT_AUTH_MODE", "disabled").strip().lower() == "local"


def cookie_secure() -> bool:
    return os.environ.get("NCT_COOKIE_SECURE", "0").strip().lower() in {"1", "true", "yes"}


def session_hours() -> int:
    try:
        return max(1, min(168, int(os.environ.get("NCT_SESSION_HOURS", "12"))))
    except ValueError:
        return 12


def normalize_username(value: object) -> str:
    username = str(value or "").strip().lower()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 2-64 lowercase letters, numbers, dots, dashes, or underscores")
    return username


def _password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be 12-256 characters")
    salt = salt or secrets.token_bytes(24)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ROUNDS)
    return base64.b64encode(salt).decode(), base64.b64encode(digest).decode()


def init_auth_storage(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_users (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES analyst_users(username)
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_auth_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL
            )"""
        )
    if not auth_enabled():
        return
    bootstrap_user = os.environ.get("NCT_BOOTSTRAP_ADMIN", "").strip()
    bootstrap_password = os.environ.get("NCT_BOOTSTRAP_PASSWORD", "")
    password_file = os.environ.get("NCT_BOOTSTRAP_PASSWORD_FILE", "").strip()
    if password_file:
        try:
            bootstrap_password = Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise RuntimeError("NCT_BOOTSTRAP_PASSWORD_FILE is not readable") from exc
    with sqlite3.connect(db_path) as db:
        count = int(db.execute("SELECT COUNT(*) FROM analyst_users").fetchone()[0])
    if count == 0:
        if not bootstrap_user or not bootstrap_password:
            raise RuntimeError(
                "NCT local authentication is enabled but no users exist. Set both "
                "NCT_BOOTSTRAP_ADMIN and NCT_BOOTSTRAP_PASSWORD_FILE for the first start."
            )
        create_user(
            db_path,
            username=bootstrap_user,
            display_name=bootstrap_user,
            role="admin",
            password=bootstrap_password,
            created_by="bootstrap",
        )


def create_user(
    db_path: Path,
    *,
    username: object,
    display_name: object,
    role: object,
    password: str,
    created_by: object,
) -> dict:
    username = normalize_username(username)
    display_name = str(display_name or "").strip()
    if not display_name or len(display_name) > 100:
        raise ValueError("Display name is required and must be 100 characters or fewer")
    role = str(role or "").strip().lower()
    if role not in ROLES:
        raise ValueError("Role must be admin, analyst, or viewer")
    actor = str(created_by or "").strip()[:100] or "system"
    salt, digest = _password_hash(password)
    changed_at = utc_now().isoformat()
    with sqlite3.connect(db_path) as db:
        try:
            db.execute(
                """INSERT INTO analyst_users (
                    username, display_name, role, password_salt, password_hash,
                    disabled, created_at, created_by
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
                (username, display_name, role, salt, digest, changed_at, actor),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That analyst username already exists") from exc
        db.execute(
            "INSERT INTO analyst_auth_audit (username, action, actor, changed_at) VALUES (?, 'create', ?, ?)",
            (username, actor, changed_at),
        )
    return {"username": username, "display_name": display_name, "role": role, "disabled": False}


def verify_credentials(db_path: Path, username: object, password: str) -> dict | None:
    try:
        username = normalize_username(username)
    except ValueError:
        return None
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM analyst_users WHERE username = ?", (username,)).fetchone()
    if row is None or row["disabled"]:
        return None
    try:
        salt = base64.b64decode(row["password_salt"])
        expected = base64.b64decode(row["password_hash"])
    except (ValueError, TypeError):
        return None
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ROUNDS)
    if not hmac.compare_digest(actual, expected):
        return None
    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
    }


def create_session(db_path: Path, username: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    created = utc_now()
    expires = created + timedelta(hours=session_hours())
    with sqlite3.connect(db_path) as db:
        db.execute(
            "INSERT INTO analyst_sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, username, created.isoformat(), expires.isoformat()),
        )
        db.execute("DELETE FROM analyst_sessions WHERE expires_at <= ?", (created.isoformat(),))
    return token, expires.isoformat()


def session_identity(db_path: Path, token: str | None) -> dict | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = utc_now().isoformat()
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """SELECT u.username, u.display_name, u.role, s.expires_at
               FROM analyst_sessions s JOIN analyst_users u ON u.username = s.username
               WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0""",
            (token_hash, now),
        ).fetchone()
    return dict(row) if row is not None else None


def end_session(db_path: Path, token: str | None) -> None:
    if not token:
        return
    with sqlite3.connect(db_path) as db:
        db.execute(
            "DELETE FROM analyst_sessions WHERE token_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )


def list_users(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute(
            "SELECT username, display_name, role, disabled, created_at, created_by FROM analyst_users ORDER BY username"
        ).fetchall()]
