"""The proxy: an MCP server whose handlers forward to an upstream MCP client."""

from __future__ import annotations

from typing import Any

from mcp.server import Server

from mcp_proxy.audit import AuditLog


def build_proxy(upstream_target: Any, audit: AuditLog, *, name: str = "mcp-proxy") -> Server:
    """Build the proxy Server.

    `upstream_target` is anything `mcp.Client` accepts (StdioServerParameters, or a
    Server/MCPServer instance for in-process tests). Use `Client(..., cache=None)`:
    we own caching policy, not the SDK.

    Handlers to implement (low-level Server takes on_* kwargs):
      on_list_tools -> forward to upstream.list_tools
      on_call_tool  -> [cache lookup] -> upstream.call_tool -> [redact] -> audit -> return
    Open the upstream client in a lifespan so it lives for the whole session.
    """
    raise NotImplementedError


def main() -> None:
    """Entry point for `mcp-proxy --config config.yaml` (stdio server)."""
    raise NotImplementedError


if __name__ == "__main__":
    main()
