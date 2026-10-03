"""The proxy: an MCP server whose handlers forward to an upstream MCP client."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import AsyncIterator
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


@dataclass
class ProxyState:
    """Per-connection state, yielded by the lifespan and available as ctx.lifespan_context."""

    upstream: Client
    audit: AuditLog | None
    session_id: str | None


def build_proxy(
    upstream_target: Any, audit: AuditLog | None = None, *, name: str = "mcp-proxy"
) -> Server[ProxyState]:
    """Build the proxy Server.

    `upstream_target` is anything `mcp.Client` accepts (StdioServerParameters, or a
    Server/MCPServer instance for in-process tests). Use `Client(..., cache=None)`:
    we own caching policy, not the SDK.

    Handlers (low-level Server takes on_* kwargs):
      on_list_tools -> forward to upstream.list_tools
      on_call_tool  -> [cache lookup] -> upstream.call_tool -> [redact] -> audit -> return
    The upstream client is opened in a lifespan so it lives for the whole session.
    If `audit` is None, calls are forwarded without being logged.
    """

    @asynccontextmanager
    async def lifespan(_: Server[ProxyState]) -> AsyncIterator[ProxyState]:
        # Runs once per connection: enter = connect upstream, exit = disconnect.
        # The yielded value becomes ctx.lifespan_context in every handler.
        async with Client(upstream_target, cache=None) as upstream:
            session_id = None
            if audit is not None:
                info = upstream.server_info
                session_id = audit.start_session(info.name if info else "unknown")
            yield ProxyState(upstream, audit, session_id)

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
        # Hook point: cache lookup goes here, before the upstream call.
        start = time.perf_counter()
        try:
            result = await state.upstream.call_tool(params.name, params.arguments)
        except Exception as exc:
            if state.audit is not None:
                state.audit.record_call(
                    state.session_id,
                    params.name,
                    params.arguments,
                    is_error=True,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    # Type only: exception messages can embed sensitive values.
                    error=type(exc).__name__,
                )
            raise
        if state.audit is not None:
            raw = result.model_dump_json(by_alias=True, exclude_none=True)
            # TODO(redaction): `result` goes through the redactor here, before logging or
            # returning. Until then result_redacted is the RAW result: don't use real data.
            state.audit.record_call(
                state.session_id,
                params.name,
                params.arguments,
                result_redacted=raw,
                result_sha256=sha256_hex(raw),
                is_error=bool(result.is_error),
                latency_ms=(time.perf_counter() - start) * 1000,
            )
        return result

    return Server(
        name, lifespan=lifespan, on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )


async def _serve(config_path: str) -> None:
    cfg = load_config(config_path)
    server = build_proxy(cfg.upstream, AuditLog(cfg.audit_db))
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
