"""Result cache (phase 3). Default-deny: only allowlisted tools are cached.

Cache the *redacted* result, never the raw one.
Key: (upstream, tool, canonical-JSON(args)). Tests should use an in-memory fake.
"""

from __future__ import annotations

from typing import Protocol


class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, ttl_seconds: int) -> None: ...


# TODO: InMemoryCache, RedisCache, make_key(upstream, tool, args)
