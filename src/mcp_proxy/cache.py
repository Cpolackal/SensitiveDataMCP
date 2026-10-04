"""Result-cache interface. Not wired into the proxy yet (see the README roadmap).

Intended policy: default-deny (only allowlisted tools), and cache the *redacted* result,
never the raw one.
"""

from __future__ import annotations

from typing import Protocol


class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, ttl_seconds: int) -> None: ...
