"""The proxy applies redaction end to end: what the model sees, what gets logged, and
that it fails closed. In-process (no subprocesses): test client -> proxy -> fake_passport."""

import json

import pytest
from mcp import Client

from fake_passport.server import TRAVELERS
from fake_passport.server import mcp as fake_passport
from mcp_proxy.audit import AuditLog, sha256_hex
from mcp_proxy.redact import FieldRegexRedactor
from mcp_proxy.server import BLOCKED_TEXT, build_proxy

REC = TRAVELERS[1]
RAW_VALUES = [REC["name"], REC["ssn"], REC["passport_number"], REC["email"], REC["phone"],
              REC["dob"], REC["address"], REC["place_of_birth"], *REC["mrz"]]  # fmt: skip


@pytest.fixture
def audit():
    a = AuditLog(":memory:")
    yield a
    a.close()


def proxy(example_redaction, audit, **kw):
    return build_proxy(fake_passport, audit, redactor_factory=example_redaction.make_redactor, **kw)


async def raw_result():
    async with Client(fake_passport) as c:
        return await c.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})


async def test_the_model_never_sees_raw_pii(example_redaction, audit):
    async with Client(proxy(example_redaction, audit)) as client:
        res = await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
    assert not res.is_error
    seen = res.model_dump_json()
    for raw in RAW_VALUES:
        assert raw not in seen, f"leaked {raw!r}"
    shown = json.loads(res.content[0].text)
    assert shown["traveler_id"] == REC["traveler_id"] and shown["nationality"] == "USA"


async def test_audit_log_holds_the_redacted_result_and_the_raw_hash(example_redaction, audit):
    async with Client(proxy(example_redaction, audit)) as client:
        await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
    (row,) = audit.query_calls()

    for raw in RAW_VALUES:
        assert raw not in row["result_redacted"], f"audit log stored {raw!r}"
    assert row["redactions_count"] == 15
    # The hash proves which data was pulled: it is the hash of the RAW result.
    raw = (await raw_result()).model_dump_json(by_alias=True, exclude_none=True)
    assert row["result_sha256"] == sha256_hex(raw)
    assert row["result_sha256"] != sha256_hex(row["result_redacted"])


async def test_arguments_are_redacted_in_the_log_but_forwarded_intact(audit):
    from mcp_proxy.config import RedactionConfig

    cfg = RedactionConfig(fields={"query": "QUERY"})  # pretend the search term is sensitive
    server = build_proxy(fake_passport, audit, redactor_factory=cfg.make_redactor)
    name = REC["name"].split()[0]
    async with Client(server) as client:
        res = await client.call_tool("search_travelers", {"query": name})
    # upstream received the real search term, so it found people...
    assert res.structured_content["result"]
    # ...but the log never saw it.
    (row,) = audit.query_calls()
    assert row["args_json"] == '{"query": "[QUERY_1]"}'


async def test_redactor_is_per_connection(example_redaction, audit):
    made = []

    def factory():
        made.append(example_redaction.make_redactor())
        return made[-1]

    server = build_proxy(fake_passport, audit, redactor_factory=factory)
    outs = []
    for _ in range(2):
        async with Client(server) as client:
            res = await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
            outs.append(json.loads(res.content[0].text))
    assert len(made) == 2 and made[0] is not made[1]
    # numbering restarts in the second session instead of continuing from the first
    assert outs[0]["ssn"] == outs[1]["ssn"] == "[SSN_1]"


async def test_one_connection_keeps_placeholders_stable_across_calls(example_redaction, audit):
    async with Client(proxy(example_redaction, audit)) as client:
        a = await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
        b = await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
    assert a.content[0].text == b.content[0].text


async def test_redaction_failure_fails_closed(audit):
    class Boom(FieldRegexRedactor):
        def redact(self, value):
            raise RuntimeError(f"cannot handle {REC['ssn']}")

    server = build_proxy(fake_passport, audit, redactor_factory=lambda: Boom({"ssn": "SSN"}, {}))
    async with Client(server) as client:
        res = await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
    assert res.is_error
    assert res.content[0].text == BLOCKED_TEXT
    assert REC["ssn"] not in res.model_dump_json()  # the exception text must not leak either


async def test_failure_is_audited_without_storing_data(audit):
    class Boom(FieldRegexRedactor):
        def redact(self, value):
            if isinstance(value, dict) and "passport_number" in value:  # only the result has it
                raise RuntimeError("boom")
            return value, 0

    server = build_proxy(fake_passport, audit, redactor_factory=lambda: Boom({}, {}))
    async with Client(server) as client:
        await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
    (row,) = audit.query_calls()
    assert row["is_error"] == 1 and row["error"] == "RuntimeError"
    assert row["result_redacted"] is None  # nothing stored...
    assert row["result_sha256"]  # ...but the pull is still provable


async def test_unredactable_arguments_block_the_call_before_it_is_forwarded(audit):
    calls = []

    class Boom(FieldRegexRedactor):
        def redact(self, value):
            raise RuntimeError("boom")

    from mcp.server.mcpserver import MCPServer

    upstream = MCPServer("spy")

    @upstream.tool()
    def ping(x: str) -> str:
        calls.append(x)
        return "pong"

    server = build_proxy(upstream, audit, redactor_factory=lambda: Boom({}, {}))
    async with Client(server) as client:
        res = await client.call_tool("ping", {"x": "hi"})
    assert res.is_error and calls == []  # upstream never saw the call


async def test_non_text_results_fail_closed(audit, example_redaction):
    from mcp.server.mcpserver import Image, MCPServer

    upstream = MCPServer("pics")

    @upstream.tool()
    def scan() -> Image:
        return Image(data=b"\x89PNG fake", format="png")

    server = build_proxy(upstream, audit, redactor_factory=example_redaction.make_redactor)
    async with Client(server) as client:
        res = await client.call_tool("scan", {})
    assert res.is_error and res.content[0].text == BLOCKED_TEXT
    assert audit.query_calls()[0]["error"] == "RedactionError"


async def test_upstream_error_results_are_blocked_or_redacted_not_raw(example_redaction, audit):
    async with Client(proxy(example_redaction, audit)) as client:
        res = await client.call_tool("get_passport", {"traveler_id": "nope"})
    assert res.is_error  # still reported as an error to the model
    assert audit.query_calls()[0]["is_error"] == 1


async def test_with_no_redactor_results_pass_through_unredacted(audit):
    # Audit-only mode (`redaction: {enabled: false}`): documents the unsafe baseline.
    async with Client(build_proxy(fake_passport, audit)) as client:
        res = await client.call_tool("get_passport", {"traveler_id": REC["traveler_id"]})
    assert REC["ssn"] in res.model_dump_json()
    assert REC["ssn"] in audit.query_calls()[0]["result_redacted"]
