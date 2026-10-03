"""SQLite audit log of sessions and tool calls.

Privacy rule: this module never receives a raw (unredacted) tool result. Callers pass
the redacted text plus `sha256_hex(raw)`, which proves *which* data was pulled without
storing it. `args_json` is whatever the caller passes, so redact arguments first if they
can contain sensitive values.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    started_at  REAL NOT NULL,
    client_name TEXT,
    upstream    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS calls (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL REFERENCES sessions(id),
    ts               REAL NOT NULL,
    tool             TEXT NOT NULL,
    args_json        TEXT,
    result_redacted  TEXT,
    result_sha256    TEXT,
    redactions_count INTEGER NOT NULL DEFAULT 0,
    cache_hit        INTEGER NOT NULL DEFAULT 0,
    is_error         INTEGER NOT NULL DEFAULT 0,
    latency_ms       REAL,
    error            TEXT
);
CREATE INDEX IF NOT EXISTS calls_session ON calls(session_id, ts);
CREATE INDEX IF NOT EXISTS calls_tool ON calls(tool, ts);
"""


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path = ":memory:") -> None:
        # The proxy is single-threaded asyncio, but guard anyway: handlers can be in flight
        # concurrently and anyio may hop threads.
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        if str(path) != ":memory:":
            # Lets `mcp-audit` read while the proxy is writing.
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def start_session(self, upstream: str, client_name: str | None = None) -> str:
        """Insert a session row and return its id."""
        sid = uuid.uuid4().hex[:12]
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO sessions (id, started_at, client_name, upstream) VALUES (?, ?, ?, ?)",
                (sid, time.time(), client_name, upstream),
            )
        return sid

    def record_call(
        self,
        session_id: str,
        tool: str,
        arguments: dict[str, Any] | None,
        *,
        result_redacted: str | None = None,
        result_sha256: str | None = None,
        redactions_count: int = 0,
        cache_hit: bool = False,
        is_error: bool = False,
        latency_ms: float | None = None,
        error: str | None = None,
    ) -> None:
        """Log one tool call (redacted result + sha256 of the raw one; see module docstring)."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO calls (session_id, ts, tool, args_json, result_redacted,"
                " result_sha256, redactions_count, cache_hit, is_error, latency_ms, error)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    time.time(),
                    tool,
                    json.dumps(arguments, sort_keys=True) if arguments is not None else None,
                    result_redacted,
                    result_sha256,
                    redactions_count,
                    int(cache_hit),
                    int(is_error),
                    latency_ms,
                    error,
                ),
            )

    def query_calls(
        self, *, session_id: str | None = None, tool: str | None = None, limit: int = 50
    ) -> list[sqlite3.Row]:
        """Most recent calls first, optionally filtered by session and/or tool."""
        sql, params = "SELECT * FROM calls WHERE 1=1", []
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        if tool:
            sql += " AND tool = ?"
            params.append(tool)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def list_sessions(self, limit: int = 20) -> list[sqlite3.Row]:
        """Most recent sessions first, each with its call count (`n_calls`)."""
        with self._lock:
            return self._db.execute(
                "SELECT s.*, (SELECT COUNT(*) FROM calls c WHERE c.session_id = s.id) AS n_calls"
                " FROM sessions s ORDER BY s.started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def close(self) -> None:
        with self._lock:
            self._db.close()
