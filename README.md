# SensitiveDataMCP

A privacy-focused MCP proxy. It sits between Claude Code and any MCP server, logs every tool call to an audit database, and (upcoming) redacts sensitive data and caches read-only results.

**Status:** skeleton. Modules are stubs with docstrings describing the plan.

## Quick start

```bash
uv sync
cp config.example.yaml config.yaml
uv run pytest
claude mcp add sensitive-proxy -e PYTHONPATH="$PWD/src" -- "$PWD/.venv/bin/mcp-proxy" --config "$PWD/config.yaml"
# once implemented: uv run mcp-audit calls --full
```

`fake_passport/` is a test MCP server that returns **synthetic** passport records (Faker). No real data is used.
