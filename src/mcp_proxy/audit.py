from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

# TODO: schema. Planned tables:
#   sessions(id, started_at, client_name, upstream)
#   calls(id, session_id, ts, tool, args_json, result_redacted, result_sha256,
#         redactions_count, cache_hit, latency_ms, error)
SCHEMA = ""


class AuditLog:
    def __init__(self, path: str | Path = ":memory:") -> None:
        raise NotImplementedError

    def start_session(self, upstream: str) -> str:
        """Insert a session row and return its id."""
        raise NotImplementedError

    def record_call(
        self,
        session_id: str,
        tool: str,
        arguments: dict[str, Any] | None,
        result: str | None,
        *,
        is_error: bool = False,
        latency_ms: float | None = None,
        error: str | None = None,
    ) -> None:
        """Log one tool call. Decide what to store: redacted result + sha256 of raw."""
        raise NotImplementedError

    def query_calls(
        self, *, session_id: str | None = None, tool: str | None = None, limit: int = 50
    ) -> list[sqlite3.Row]:
        raise NotImplementedError

    def list_sessions(self, limit: int = 20) -> list[sqlite3.Row]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
