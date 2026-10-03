from mcp import Client

from fake_passport.server import mcp as fake_passport
from mcp_proxy.audit import AuditLog, sha256_hex
from mcp_proxy.server import build_proxy


async def test_lists_upstream_tools():
    async with Client(build_proxy(fake_passport)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert {"search_travelers", "get_passport", "get_visa_history"} <= names


async def test_call_is_forwarded():
    async with Client(build_proxy(fake_passport)) as client:
        res = await client.call_tool("search_travelers", {"query": ""})
    assert not res.is_error
    assert len(res.structured_content["result"]) == 10


async def test_upstream_error_is_passed_through():
    async with Client(build_proxy(fake_passport)) as client:
        res = await client.call_tool("get_passport", {"traveler_id": "nope"})
    assert res.is_error


async def test_call_is_logged():
    audit = AuditLog(":memory:")
    async with Client(build_proxy(fake_passport, audit)) as client:
        res = await client.call_tool("get_visa_history", {"traveler_id": "T1000"})
    assert not res.is_error

    (sess,) = audit.list_sessions()
    assert sess["upstream"] == "fake-passport"
    assert sess["n_calls"] == 1

    (row,) = audit.query_calls()
    assert row["session_id"] == sess["id"]
    assert row["tool"] == "get_visa_history"
    assert row["args_json"] == '{"traveler_id": "T1000"}'
    assert row["is_error"] == 0
    assert row["latency_ms"] > 0
    # Hash covers exactly what was stored (no redaction yet, so they match).
    assert row["result_sha256"] == sha256_hex(row["result_redacted"])


async def test_upstream_error_result_is_logged_as_error():
    audit = AuditLog(":memory:")
    async with Client(build_proxy(fake_passport, audit)) as client:
        res = await client.call_tool("get_passport", {"traveler_id": "nope"})
    assert res.is_error
    assert audit.query_calls()[0]["is_error"] == 1


async def test_calls_in_one_connection_share_a_session():
    audit = AuditLog(":memory:")
    async with Client(build_proxy(fake_passport, audit)) as client:
        await client.call_tool("search_travelers", {"query": "a"})
        await client.call_tool("search_travelers", {"query": "b"})
    (sess,) = audit.list_sessions()
    assert sess["n_calls"] == 2


async def test_each_connection_gets_its_own_session():
    audit = AuditLog(":memory:")
    for _ in range(2):
        async with Client(build_proxy(fake_passport, audit)) as client:
            await client.call_tool("search_travelers", {"query": ""})
    assert len(audit.list_sessions()) == 2
