"""The proxy: an MCP server whose handlers forward to an upstream MCP client."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import anyio
import mcp_types as types
from mcp import Client
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from mcp_proxy.audit import AuditLog, sha256_hex
from mcp_proxy.config import ConfigError, load_config
from mcp_proxy.redact import Redactor
from mcp_proxy.results import redact_call_result


@dataclass
class ProxyState:
    """Per-connection state, yielded by the lifespan and available as ctx.lifespan_context."""

    upstream: Client
    audit: AuditLog | None
    session_id: str | None
    redactor: Redactor | None  # one per connection: its state is the session's state


BLOCKED_TEXT = "Blocked by the sensitive-data proxy: this result could not be redacted safely."


def _blocked_result() -> types.CallToolResult:
    """What the model sees when redaction fails. Deliberately says nothing about the data."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=BLOCKED_TEXT)], is_error=True
    )


def build_proxy(
    upstream_target: Any,
    audit: AuditLog | None = None,
    *,
    redactor_factory: Callable[[], Redactor | None] | None = None,
    name: str = "mcp-proxy",
) -> Server[ProxyState]:
    """Build the proxy Server.

    `upstream_target` is anything `mcp.Client` accepts: a StdioServerParameters, or a
    Server/MCPServer instance for in-process tests. `tools/list` is forwarded as-is;
    `tools/call` runs: redact arguments for the log -> upstream call -> redact result ->
    audit -> return.

    `audit=None` skips logging. `redactor_factory` is called once per connection, because
    placeholders and known values are per session; with None, results pass through
    UNREDACTED.
    """

    @asynccontextmanager
    async def lifespan(_: Server[ProxyState]) -> AsyncIterator[ProxyState]:
        # Runs once per connection: enter = connect upstream, exit = disconnect.
        # The yielded value becomes ctx.lifespan_context in every handler.
        # cache=None turns off the SDK's own response cache so it can't serve stale results.
        async with Client(upstream_target, cache=None) as upstream:
            session_id = None
            if audit is not None:
                info = upstream.server_info
                session_id = audit.start_session(info.name if info else "unknown")
            redactor = redactor_factory() if redactor_factory else None
            yield ProxyState(upstream, audit, session_id, redactor)

    async def on_list_tools(
        ctx: ServerRequestContext[ProxyState], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        # Forward the pagination cursor so large upstream tool lists still work.
        return await ctx.lifespan_context.upstream.list_tools(
            cursor=params.cursor if params else None
        )

    async def on_call_tool(
        ctx: ServerRequestContext[ProxyState], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        state = ctx.lifespan_context
        start = time.perf_counter()

        def log(tool_args, *, result_redacted=None, raw=None, count=0, is_error=False, error=None):
            if state.audit is None:
                return
            state.audit.record_call(
                state.session_id,
                params.name,
                tool_args,
                result_redacted=result_redacted,
                result_sha256=sha256_hex(raw) if raw is not None else None,
                redactions_count=count,
                is_error=is_error,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=error,
            )

        # Arguments can hold sensitive values (a search by name), so the audit log gets a
        # redacted copy; upstream still receives the original. If we can't redact, fail
        # closed *before* forwarding anything.
        logged_args = params.arguments
        if state.redactor is not None and params.arguments is not None:
            try:
                logged_args, _ = state.redactor.redact(params.arguments)
            except Exception as exc:
                log(None, is_error=True, error=type(exc).__name__)
                return _blocked_result()

        try:
            result = await state.upstream.call_tool(params.name, params.arguments)
        except Exception as exc:
            # Type only: exception messages can embed sensitive values.
            log(logged_args, is_error=True, error=type(exc).__name__)
            raise

        raw = result.model_dump_json(by_alias=True, exclude_none=True)
        if state.redactor is None:
            # Redaction disabled in config: audit-only mode.
            log(logged_args, result_redacted=raw, raw=raw, is_error=bool(result.is_error))
            return result

        try:
            safe, count = redact_call_result(state.redactor, result)
        except Exception as exc:
            # Fail closed: never fall back to the raw result. The hash still records which
            # data was pulled, without storing it.
            log(logged_args, raw=raw, is_error=True, error=type(exc).__name__)
            return _blocked_result()

        log(
            logged_args,
            result_redacted=safe.model_dump_json(by_alias=True, exclude_none=True),
            raw=raw,
            count=count,
            is_error=bool(result.is_error),
        )
        return safe

    return Server(
        name, lifespan=lifespan, on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )


async def _serve(config_path: str) -> None:
    cfg = load_config(config_path)
    if not cfg.redaction.enabled:
        print("mcp-proxy: WARNING: redaction is disabled; results are NOT redacted", file=sys.stderr)
    server = build_proxy(
        cfg.upstream, AuditLog(cfg.audit_db), redactor_factory=cfg.redaction.make_redactor
    )
    # stdout is the protocol channel in stdio mode: never print to it.
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    """Entry point for `mcp-proxy --config config.yaml` (stdio server)."""
    parser = argparse.ArgumentParser(prog="mcp-proxy", description=__doc__)
    parser.add_argument("--config", default="config.yaml", help="path to the YAML config")
    args = parser.parse_args()
    try:
        anyio.run(_serve, args.config)
    except ConfigError as exc:
        print(f"mcp-proxy: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
