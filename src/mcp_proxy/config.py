from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from mcp import StdioServerParameters


class ConfigError(Exception):
    """Raised for a missing, unparseable, or invalid config file."""


@dataclass
class Config:
    upstream: StdioServerParameters
    audit_db: Path = field(default_factory=lambda: Path("audit.sqlite"))
    # TODO: redaction rules, cache allowlist (tool -> ttl), redis_url, store_raw


def load_config(path: str | Path) -> Config:
    """Parse the YAML file (see config.example.yaml) into a Config.

    Relative paths resolve against the config file's directory, not the process cwd,
    because the host (Claude Code) can launch the proxy from anywhere. That covers
    `log.db`, and the upstream's working directory (so relative paths in
    `upstream.args` work).
    """
    path = Path(path).expanduser()
    try:
        text = path.read_text()
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")

    base = path.resolve().parent
    return Config(
        upstream=_parse_upstream(raw.get("upstream"), base),
        audit_db=_resolve(_parse_log(raw.get("log")), base),
    )


def _resolve(p: str | Path, base: Path) -> Path:
    p = Path(p).expanduser()
    return p if p.is_absolute() else base / p


def _parse_upstream(up: Any, base: Path) -> StdioServerParameters:
    if not isinstance(up, dict):
        raise ConfigError("`upstream` is required and must be a mapping")
    command = up.get("command")
    if not isinstance(command, str) or not command:
        raise ConfigError("`upstream.command` is required and must be a non-empty string")

    args = up.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, (str, int, float)) for a in args):
        raise ConfigError("`upstream.args` must be a list of strings")

    env = up.get("env")
    if env is not None and (
        not isinstance(env, dict) or not all(isinstance(k, str) for k in env)
    ):
        raise ConfigError("`upstream.env` must be a mapping of names to values")

    cwd = up.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise ConfigError("`upstream.cwd` must be a string")

    return StdioServerParameters(
        command=command,
        args=[str(a) for a in args],
        env={k: str(v) for k, v in env.items()} if env else None,
        cwd=_resolve(cwd, base) if cwd else base,
    )


def _parse_log(log: Any) -> str:
    if log is None:
        return "audit.sqlite"
    if not isinstance(log, dict):
        raise ConfigError("`log` must be a mapping")
    db = log.get("db", "audit.sqlite")
    if not isinstance(db, str) or not db:
        raise ConfigError("`log.db` must be a non-empty string")
    return db
