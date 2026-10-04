from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from mcp import StdioServerParameters

from mcp_proxy.redact import FieldRegexRedactor, Redactor


class ConfigError(Exception):
    """Raised for a missing, unparseable, or invalid config file."""


@dataclass
class RedactionConfig:
    """Redaction rules. `enabled=False` is the explicit opt-out (audit-only proxy)."""

    enabled: bool = True
    fields: dict[str, str] = field(default_factory=dict)  # JSON key -> label
    patterns: dict[str, str] = field(default_factory=dict)  # label -> regex

    def make_redactor(self) -> Redactor | None:
        """A fresh redactor. Call once per connection: placeholder numbering and known
        values are per session, so instances must never be shared across connections."""
        if not self.enabled:
            return None
        return FieldRegexRedactor(self.fields, self.patterns)


@dataclass
class Config:
    upstream: StdioServerParameters
    redaction: RedactionConfig
    audit_db: Path = field(default_factory=lambda: Path("audit.sqlite"))
    # TODO: cache allowlist (tool -> ttl), redis_url, store_raw


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
        redaction=_parse_redaction(raw.get("redaction")),
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


def _str_mapping(value: Any, name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise ConfigError(f"`{name}` must be a mapping of strings to strings")
    return value


def _parse_redaction(red: Any) -> RedactionConfig:
    if red is None:
        # Required on purpose: silently running unredacted is the worst failure mode here.
        raise ConfigError(
            "`redaction` is required (add `fields`/`patterns`, or `redaction: {enabled: false}`"
            " to log without redacting)"
        )
    if not isinstance(red, dict):
        raise ConfigError("`redaction` must be a mapping")
    enabled = red.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError("`redaction.enabled` must be true or false")

    cfg = RedactionConfig(
        enabled=enabled,
        fields=_str_mapping(red.get("fields"), "redaction.fields"),
        patterns=_str_mapping(red.get("patterns"), "redaction.patterns"),
    )
    if enabled:
        if not cfg.fields and not cfg.patterns:
            raise ConfigError(
                "`redaction` enabled but has no `fields` or `patterns`, so it would redact"
                " nothing (use `enabled: false` if that is intended)"
            )
        try:
            FieldRegexRedactor(cfg.fields, cfg.patterns)  # validate labels and regexes now
        except ValueError as exc:
            raise ConfigError(f"invalid `redaction` config: {exc}") from exc
    return cfg
