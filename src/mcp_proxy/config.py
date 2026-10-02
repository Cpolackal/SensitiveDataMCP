from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp import StdioServerParameters


@dataclass
class Config:
    upstream: StdioServerParameters
    audit_db: Path = field(default_factory=lambda: Path("audit.sqlite"))
    # TODO: redaction rules, cache allowlist (tool -> ttl), redis_url, store_raw


def load_config(path: str | Path) -> Config:
    """Parse the YAML file (see config.example.yaml) into a Config."""
    raise NotImplementedError
