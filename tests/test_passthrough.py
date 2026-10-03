import pytest
from mcp import Client

from fake_passport.server import mcp as fake_passport
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


@pytest.mark.skip(reason="needs audit log")
async def test_call_is_logged():
    ...
