"""Proxy behavior beyond the fake_passport happy path, using small purpose-built upstreams.

Covers: learning from arguments, error paths, pagination, concurrency within one
connection, and what is (not) redacted outside tool results. Known gaps are
`xfail(strict=True)`, so a fix makes the suite fail until the marker is removed.
"""

from __future__ import annotations

import json

import anyio
import mcp_types as types
import pytest
from mcp import Client, MCPError
from mcp.server import Server
from mcp.server.mcpserver import MCPServer

from mcp_proxy.audit import AuditLog
from mcp_proxy.server import build_proxy

SSN = "242-47-3361"
NAME = "Gregory Moore"


@pytest.fixture
def audit():
    a = AuditLog(":memory:")
    yield a
    a.close()


def proxy(upstream, example_redaction, audit):
    return build_proxy(upstream, audit, redactor_factory=example_redaction.make_redactor)


def raising_upstream(exc: Exception) -> Server:
    """A low-level upstream whose only tool raises `exc` from the request handler, so the
    failure surfaces as a JSON-RPC error rather than an is_error tool result."""

    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=[types.Tool(name="boom", input_schema={"type": "object"})])

    async def call_tool(ctx, params):
        raise exc

    return Server("raiser", on_list_tools=list_tools, on_call_tool=call_tool)


# ------------------------------------------------------------------ arguments


async def test_sensitive_arguments_are_forwarded_raw_and_teach_the_redactor(example_redaction, audit):
    received = []
    upstream = MCPServer("lookup")

    @upstream.tool()
    def lookup(name: str) -> str:
        received.append(name)
        return f"Record found for {name}; no flags."

    async with Client(proxy(upstream, example_redaction, audit)) as client:
        res = await client.call_tool("lookup", {"name": NAME})

    assert received == [NAME]  # upstream gets the real value
    assert NAME not in res.model_dump_json()  # learned from the argument, so caught in prose
    assert "[PERSON_1]" in res.content[0].text
    (row,) = audit.query_calls()
    assert json.loads(row["args_json"]) == {"name": "[PERSON_1]"}
    assert NAME not in row["result_redacted"]


# ---------------------------------------------------------------- error paths


async def test_unexpected_upstream_exception_reaches_the_model_without_its_message(
    example_redaction, audit
):
    upstream = raising_upstream(ValueError(f"lookup failed for SSN {SSN}"))
    async with Client(proxy(upstream, example_redaction, audit)) as client:
        with pytest.raises(MCPError) as info:
            await client.call_tool("boom", {})
    assert SSN not in str(info.value)  # the SDK replaces it with "Internal server error"
    (row,) = audit.query_calls()
    assert row["is_error"] == 1 and row["error"] == "MCPError"
    assert row["result_redacted"] is None and row["result_sha256"] is None


async def test_upstream_error_message_is_redacted(example_redaction, audit):
    upstream = raising_upstream(MCPError(code=-32000, message=f"lookup failed for SSN {SSN}"))
    async with Client(proxy(upstream, example_redaction, audit)) as client:
        with pytest.raises(MCPError) as info:
            await client.call_tool("boom", {})
    assert info.value.code == -32000  # the error stays the same kind of error
    assert info.value.message == "lookup failed for SSN [SSN_1]"
    (row,) = audit.query_calls()
    assert row["error"] == "MCPError" and SSN not in (row["args_json"] or "")


async def test_upstream_error_data_is_redacted(example_redaction, audit):
    exc = MCPError(code=-32000, message="lookup failed", data={"name": NAME, "ssn": SSN})
    async with Client(proxy(raising_upstream(exc), example_redaction, audit)) as client:
        with pytest.raises(MCPError) as info:
            await client.call_tool("boom", {})
    assert info.value.data == {"name": "[PERSON_1]", "ssn": "[SSN_1]"}


async def test_upstream_error_uses_values_learned_from_arguments(example_redaction, audit):
    exc = MCPError(code=-32000, message=f"no record for {NAME}")
    async with Client(proxy(raising_upstream(exc), example_redaction, audit)) as client:
        with pytest.raises(MCPError) as info:
            await client.call_tool("boom", {"name": NAME})
    assert info.value.message == "no record for [PERSON_1]"


async def test_unredactable_upstream_error_is_withheld(audit):
    from mcp_proxy.redact import FieldRegexRedactor
    from mcp_proxy.server import WITHHELD_ERROR_TEXT

    class Boom(FieldRegexRedactor):
        def redact(self, value):
            if isinstance(value, dict) and "message" in value:  # only the error path
                raise RuntimeError("boom")
            return value, 0

    upstream = raising_upstream(MCPError(code=-32001, message=f"SSN {SSN}", data=SSN))
    server = build_proxy(upstream, audit, redactor_factory=lambda: Boom({}, {}))
    async with Client(server) as client:
        with pytest.raises(MCPError) as info:
            await client.call_tool("boom", {})
    assert info.value.code == -32001
    assert info.value.message == WITHHELD_ERROR_TEXT and info.value.data is None


async def test_with_no_redactor_upstream_errors_pass_through(audit):
    # Audit-only mode (`redaction: {enabled: false}`): documents the unsafe baseline.
    upstream = raising_upstream(MCPError(code=-32000, message=f"SSN {SSN}"))
    async with Client(build_proxy(upstream, audit)) as client:
        with pytest.raises(MCPError) as info:
            await client.call_tool("boom", {})
    assert info.value.message == f"SSN {SSN}"


async def test_unknown_tool_is_an_error_not_a_crash(example_redaction, audit):
    async with Client(proxy(MCPServer("empty"), example_redaction, audit)) as client:
        try:
            res = await client.call_tool("does_not_exist", {})
        except MCPError:
            pass
        else:
            assert res.is_error
        # The connection survives for the next call.
        assert (await client.list_tools()).tools == []


# ------------------------------------------------------------------ list_tools


async def test_list_tools_forwards_the_pagination_cursor():
    pages = {None: (["a", "b"], "page2"), "page2": (["c"], None)}

    async def list_tools(ctx, params):
        names, nxt = pages[params.cursor if params else None]
        tools = [types.Tool(name=n, input_schema={"type": "object"}) for n in names]
        return types.ListToolsResult(tools=tools, next_cursor=nxt)

    upstream = Server("paged", on_list_tools=list_tools)
    async with Client(build_proxy(upstream)) as client:
        first = await client.list_tools()
        second = await client.list_tools(cursor=first.next_cursor)
    assert [t.name for t in first.tools] == ["a", "b"] and first.next_cursor == "page2"
    assert [t.name for t in second.tools] == ["c"] and second.next_cursor is None


@pytest.mark.xfail(strict=True, reason="LIMITATION: tool descriptions pass through unredacted")
async def test_tool_descriptions_are_redacted(example_redaction, audit):
    upstream = MCPServer("chatty")

    @upstream.tool(description=f"Looks up records. Example SSN: {SSN}")
    def lookup(q: str) -> str:
        return "ok"

    async with Client(proxy(upstream, example_redaction, audit)) as client:
        tools = await client.list_tools()
    assert SSN not in tools.model_dump_json()


# ---------------------------------------------------------------- results


async def test_pii_used_as_a_result_key_does_not_reach_the_model(example_redaction, audit):
    upstream = MCPServer("index")

    @upstream.tool()
    def visits_by_email() -> dict:
        return {"janetclay@example.net": 3}

    async with Client(proxy(upstream, example_redaction, audit)) as client:
        res = await client.call_tool("visits_by_email", {})
    assert "janetclay@example.net" not in res.model_dump_json()
    assert json.loads(res.content[0].text) == {"[EMAIL_1]": 3}
    assert "janetclay@example.net" not in audit.query_calls()[0]["result_redacted"]


async def test_colliding_result_keys_are_blocked(example_redaction, audit):
    from mcp_proxy.server import BLOCKED_TEXT

    upstream = MCPServer("index")

    @upstream.tool()
    def visits_by_email() -> dict:
        return {"janetclay@example.net": 3, "JANETCLAY@example.net": 4}

    async with Client(proxy(upstream, example_redaction, audit)) as client:
        res = await client.call_tool("visits_by_email", {})
    assert res.is_error and res.content[0].text == BLOCKED_TEXT
    assert audit.query_calls()[0]["error"] == "RedactionError"


async def test_concurrent_calls_on_one_connection_share_placeholders(example_redaction, audit):
    upstream = MCPServer("slow")

    @upstream.tool()
    async def record(delay: float) -> dict:
        await anyio.sleep(delay)
        return {"name": NAME, "ssn": SSN, "notes": f"{NAME} verified"}

    results = {}
    async with Client(proxy(upstream, example_redaction, audit)) as client:

        async def call(delay):
            results[delay] = await client.call_tool("record", {"delay": delay})

        async with anyio.create_task_group() as tg:
            for delay in (0.05, 0.0, 0.02):
                tg.start_soon(call, delay)

    texts = {json.loads(r.content[0].text)["notes"] for r in results.values()}
    assert texts == {"[PERSON_1] verified"}
    assert len(audit.query_calls()) == 3
    assert {row["redactions_count"] for row in audit.query_calls()} == {3}


async def test_plain_text_results_are_redacted(example_redaction, audit):
    upstream = MCPServer("prose")

    @upstream.tool()
    def note() -> str:
        return f"Caller gave SSN {SSN} and email janetclay@example.net."

    async with Client(proxy(upstream, example_redaction, audit)) as client:
        res = await client.call_tool("note", {})
    seen = res.model_dump_json()
    assert SSN not in seen and "janetclay@example.net" not in seen
    assert "[SSN_1]" in res.content[0].text and "[EMAIL_1]" in res.content[0].text
