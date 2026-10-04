"""Redacting an MCP tool result.

A CallToolResult carries the same data in several places (`structured_content`, and JSON
text inside `content[].text`). Every copy must be redacted, or the model just reads the
unredacted one. Only the pieces the model reads are touched: not `_meta`, whose keys
(e.g. serverInfo.name) would collide with sensitive field names like "name".
"""

from __future__ import annotations

import json

import mcp_types as types

from mcp_proxy.redact import RedactionError, Redactor


def redact_call_result(
    redactor: Redactor, result: types.CallToolResult
) -> tuple[types.CallToolResult, int]:
    """Return (redacted copy, number of redactions). Raises on anything it can't handle.

    The input is not mutated. Callers must treat any exception as "withhold the result".
    """
    total = 0

    structured = result.structured_content
    if structured is not None:
        structured, n = redactor.redact(structured)
        total += n

    blocks = []
    for block in result.content:
        # Fail closed: images, audio, links and embedded resources can carry sensitive data
        # (a scanned passport, a name in a link title) that text redaction can't see.
        if not isinstance(block, types.TextContent):
            raise RedactionError(f"unsupported content block type {block.type!r}")
        text, n = _redact_text(redactor, block.text)
        blocks.append(block.model_copy(update={"text": text}))
        total += n

    redacted = result.model_copy(update={"content": blocks, "structured_content": structured})
    return redacted, total


def _redact_text(redactor: Redactor, text: str) -> tuple[str, int]:
    """Text that is a JSON object/array is redacted as a structure (so field-name rules
    apply); anything else is redacted as free text."""
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, (dict, list)):
        redacted, n = redactor.redact(parsed)
        return json.dumps(redacted, ensure_ascii=False), n
    redacted_text, n = redactor.redact(text)
    return redacted_text, n
