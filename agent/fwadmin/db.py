"""SQLite para o que e' runtime, nunca para configuracao.

Aqui moram usuarios, sessoes e o log de auditoria: dado tabular, volatil e
consultavel. A configuracao do firewall vive no config.yaml versionado — se
este banco sumir, o firewall continua funcionando exatamente igual.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from fwadmin import paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,          -- 'pam': a senha e' a do sistema
    created_at REAL NOT NULL,
    last_login REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    address    TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY,
    at        REAL NOT NULL,
    username  TEXT,
    address   TEXT,
    action    TEXT NOT NULL,
    detail    TEXT
);

CREATE INDEX IF NOT EXISTS audit_at ON audit(at DESC);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at);
"""

SESSION_TTL = 12 * 3600


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    paths.DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(paths.DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# usuarios
# ---------------------------------------------------------------------------


def ensure_user(username: str) -> int:
    """O id do usuario, criando a linha no primeiro login. A senha nao mora
    aqui: quem confere e' o PAM (fwctl login). A tabela so ancora sessoes e o
    ultimo acesso."""
    now = time.time()
    with connect() as conn:
        conn.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, 'pam', ?)"
            " ON CONFLICT(username) DO NOTHING",
            (username, now),
        )
        conn.execute("UPDATE users SET last_login = ? WHERE username = ?", (now, username))
        return conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


# ---------------------------------------------------------------------------
# sessoes
# ---------------------------------------------------------------------------


@dataclass
class Session:
    token: str
    username: str
    expires_at: float


def open_session(user_id: int, address: str = "") -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at, address)"
            " VALUES (?, ?, ?, ?, ?)",
            (token, user_id, now, now + SESSION_TTL, address),
        )
    return token


def get_session(token: str) -> Session | None:
    if not token:
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT s.token, s.expires_at, u.username FROM sessions s"
            " JOIN users u ON u.id = s.user_id"
            " WHERE s.token = ? AND s.expires_at > ?",
            (token, time.time()),
        ).fetchone()
    return Session(row["token"], row["username"], row["expires_at"]) if row else None


def close_session(token: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


# ---------------------------------------------------------------------------
# auditoria
# ---------------------------------------------------------------------------


def log(action: str, username: str = "", address: str = "", **detail: Any) -> None:
    """Registra o que foi feito. Toda mudanca de config passa por aqui."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit (at, username, address, action, detail) VALUES (?, ?, ?, ?, ?)",
            (time.time(), username, address, action, json.dumps(detail) if detail else None),
        )


def recent(limit: int = 50) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM audit ORDER BY at DESC LIMIT ?", (limit,)
        ).fetchall()
