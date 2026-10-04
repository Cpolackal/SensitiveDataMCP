"""redact_call_result: every copy of the data in a tool result gets redacted."""

import copy

import mcp_types as types
import pytest

from mcp_proxy.redact import FieldRegexRedactor, RedactionError
from mcp_proxy.results import redact_call_result


@pytest.fixture
def redactor(example_redaction):
    return example_redaction.make_redactor()


def result(*texts, structured=None, meta=None, **extra):
    data = {"content": [{"type": "text", "text": t} for t in texts], **extra}
    if structured is not None:
        data["structuredContent"] = structured
    if meta is not None:
        data["_meta"] = meta
    return types.CallToolResult.model_validate(data)


RECORD = {"name": "Tammy Alexander", "ssn": "048-35-9117", "traveler_id": "T1000"}


def test_structured_content_and_json_text_are_both_redacted_consistently(redactor):
    import json

    res = result(json.dumps(RECORD), structured=RECORD)
    out, count = redact_call_result(redactor, res)
    assert out.structured_content == {"name": "[PERSON_1]", "ssn": "[SSN_1]", "traveler_id": "T1000"}
    # the text copy is parsed as JSON, so the field rules apply to it too
    assert json.loads(out.content[0].text) == out.structured_content
    assert count == 4


def test_json_array_text_is_parsed(redactor):
    import json

    out, _ = redact_call_result(redactor, result(json.dumps([RECORD, {"ssn": "111-22-3333"}])))
    assert json.loads(out.content[0].text) == [
        {"name": "[PERSON_1]", "ssn": "[SSN_1]", "traveler_id": "T1000"},
        {"ssn": "[SSN_2]"},
    ]


def test_plain_text_gets_the_regex_pass(redactor):
    out, count = redact_call_result(redactor, result("No match for 048-35-9117 (a@example.com)"))
    assert out.content[0].text == "No match for [SSN_1] ([EMAIL_1])" and count == 2


@pytest.mark.parametrize("text", ["123", "true", "null", '"just a json string 048-35-9117"'])
def test_non_container_json_is_treated_as_text(redactor, text):
    out, _ = redact_call_result(redactor, result(text))
    assert "048-35-9117" not in out.content[0].text


def test_is_error_results_are_redacted_too(redactor):
    out, _ = redact_call_result(redactor, result("lookup failed for 048-35-9117", isError=True))
    assert out.is_error and "048" not in out.content[0].text


def test_meta_is_left_alone(redactor):
    # serverInfo.name would be redacted as a PERSON if _meta were walked.
    meta = {"io.modelcontextprotocol/serverInfo": {"name": "fake-passport"}}
    out, _ = redact_call_result(redactor, result("ok", meta=meta))
    assert out.meta == meta


def test_input_is_not_mutated(redactor):
    import json

    res = result(json.dumps(RECORD), structured=RECORD)
    snapshot = copy.deepcopy(res.model_dump())
    redact_call_result(redactor, res)
    assert res.model_dump() == snapshot


@pytest.mark.parametrize(
    "block",
    [
        {"type": "image", "data": "aGk=", "mimeType": "image/png"},
        {"type": "audio", "data": "aGk=", "mimeType": "audio/wav"},
        {"type": "resource_link", "uri": "file:///a", "name": "Tammy Alexander passport"},
        {"type": "resource", "resource": {"uri": "file:///a", "text": "048-35-9117"}},
    ],
)
def test_non_text_blocks_fail_closed(redactor, block):
    res = types.CallToolResult.model_validate({"content": [{"type": "text", "text": "hi"}, block]})
    with pytest.raises(RedactionError, match="unsupported content block"):
        redact_call_result(redactor, res)


def test_error_message_does_not_contain_the_data(redactor):
    res = types.CallToolResult.model_validate(
        {"content": [{"type": "resource", "resource": {"uri": "file:///a", "text": "048-35-9117"}}]}
    )
    with pytest.raises(RedactionError) as exc:
        redact_call_result(redactor, res)
    assert "048-35-9117" not in str(exc.value)


def test_works_with_any_redactor():
    class Upper:
        def redact(self, value):
            return (value.upper(), 1) if isinstance(value, str) else (value, 0)

    out, count = redact_call_result(Upper(), result("hello"))
    assert out.content[0].text == "HELLO" and count == 1


def test_a_failing_redactor_propagates():
    class Boom(FieldRegexRedactor):
        def redact(self, value):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        redact_call_result(Boom({}, {}), result("x"))
