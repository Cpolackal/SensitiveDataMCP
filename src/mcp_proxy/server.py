"""The proxy: an MCP server whose handlers forward to an upstream MCP client."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import mcp_types as types
from mcp import Client
from mcp.server import Server, ServerRequestContext

from mcp_proxy.audit import AuditLog


def build_proxy(
    upstream_target: Any, audit: AuditLog | None = None, *, name: str = "mcp-proxy"
) -> Server[Client]:
    """Build the proxy Server.

    `upstream_target` is anything `mcp.Client` accepts (StdioServerParameters, or a
    Server/MCPServer instance for in-process tests). Use `Client(..., cache=None)`:
    we own caching policy, not the SDK.

    Handlers (low-level Server takes on_* kwargs):
      on_list_tools -> forward to upstream.list_tools
      on_call_tool  -> [cache lookup] -> upstream.call_tool -> [redact] -> audit -> return
    The upstream client is opened in a lifespan so it lives for the whole session.
    """

    @asynccontextmanager
    async def lifespan(_: Server[Client]) -> AsyncIterator[Client]:
        # Runs once per connection: enter = connect upstream, exit = disconnect.
        # The yielded value becomes ctx.lifespan_context in every handler.
        async with Client(upstream_target, cache=None) as upstream:
            yield upstream

    async def on_list_tools(
        ctx: ServerRequestContext[Client], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        # Forward the pagination cursor so large upstream tool lists still work.
        return await ctx.lifespan_context.list_tools(cursor=params.cursor if params else None)

    async def on_call_tool(
        ctx: ServerRequestContext[Client], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        # Hook point: cache lookup before, redact + audit after.
        return await ctx.lifespan_context.call_tool(params.name, params.arguments)

    return Server(
        name, lifespan=lifespan, on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )


def main() -> None:
    """Entry point for `mcp-proxy --config config.yaml` (stdio server)."""
    raise NotImplementedError


if __name__ == "__main__":
    main()
