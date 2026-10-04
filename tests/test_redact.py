"""The redaction contract for `FieldRegexRedactor(fields, patterns)`.

`fields` maps a JSON key name to a label ({"ssn": "SSN"}); `patterns` maps a label to a
regex for free text. `redact(value) -> (redacted_value, count)`. One instance is one
session: placeholder numbering and known values persist across calls on the same instance.

Behavior pinned down here
  * Field pass: the value under a sensitive key (case-insensitive) is replaced entirely
    ("[LABEL_N]"), at any depth. Keys are never changed. None stays None.
  * Regex pass: every match of a label's pattern inside any string is replaced.
  * Known-value propagation: a string seen under a sensitive key is remembered and is
    replaced everywhere it appears in free text (case-insensitive, whole-token), in any
    key order and in later calls. Values shorter than 4 chars are not propagated.
    This is what catches names and bare 9/10-digit numbers that no regex can.
  * Placeholders: "[LABEL_N]", N counts from 1 per label in first-seen order. The same value
    (case-insensitive, trimmed) always gets the same placeholder.
  * Count = number of replaced occurrences.
  * Idempotent: placeholders are never re-redacted (a placeholder under a sensitive key stays).
  * Fails closed: anything that is not JSON-like raises RedactionError, never passes through.
  * The input is never mutated.

Known limitations (deliberately NOT tested as leaks): a bare 9/10-digit number or a name that
never appeared in a sensitive field cannot be detected, and is left alone.
"""

from __future__ import annotations

import copy
import json
import re

import pytest

from fake_passport.server import TRAVELERS
from mcp_proxy.redact import FieldRegexRedactor, RedactionError

FIELDS = {
    "ssn": "SSN",
    "passport_number": "PASSPORT",
    "email": "EMAIL",
    "phone": "PHONE",
    "dob": "DOB",
    "name": "PERSON",
    "address": "ADDRESS",
    "place_of_birth": "LOCATION",
    "mrz": "MRZ",
}

PATTERNS = {
    "SSN": r"(?<![\w-])\d{3}[- ]\d{2}[- ]\d{4}(?![\w-])",
    "EMAIL": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
    # Separators are required between groups, so bare 10-digit numbers do not match.
    "PHONE": (
        r"(?<![\w.-])(?:\+1[-. ]?|001[-. ])?(?:\(\d{3}\)|\d{3})[-. ]?\d{3}[-. ]\d{4}"
        r"(?:x\d{1,5})?(?![\w-])"
    ),
    "PASSPORT": r"(?<![\w-])[A-Z]\d{8}(?![\w-])",
    "MRZ": r"(?<![A-Z0-9<])[A-Z0-9<]{44}(?![A-Z0-9<])",
}

PLACEHOLDER = re.compile(r"^\[[A-Z]+_\d+\]$")


@pytest.fixture
def r():
    return FieldRegexRedactor(fields=FIELDS, patterns=PATTERNS)


def fresh():
    return FieldRegexRedactor(fields=FIELDS, patterns=PATTERNS)


# --------------------------------------------------------------------------- structure


def test_returns_value_and_count(r):
    assert r.redact("nothing sensitive here") == ("nothing sensitive here", 0)


def test_input_is_not_mutated(r):
    record = {"ssn": "048-35-9117", "notes": "call 240.559.4189", "tags": ["a", {"email": "x@y.com"}]}
    snapshot = copy.deepcopy(record)
    r.redact(record)
    assert record == snapshot


def test_keys_are_preserved(r):
    out, _ = r.redact({"ssn": "048-35-9117", "Name": "Tammy Alexander", "extra": {"dob": "1951-06-20"}})
    assert set(out) == {"ssn", "Name", "extra"}
    assert set(out["extra"]) == {"dob"}


@pytest.mark.parametrize("scalar", [0, 42, 3.14, True, False, None])
def test_non_sensitive_scalars_pass_through(r, scalar):
    assert r.redact(scalar) == (scalar, 0)
    out, count = r.redact({"visits": scalar})
    assert out == {"visits": scalar} and count == 0


def test_nested_structures_are_walked(r):
    data = [{"people": [{"profile": {"email": "a@example.com"}}], "meta": {"x": 1}}]
    out, count = r.redact(data)
    assert out[0]["people"][0]["profile"]["email"] == "[EMAIL_1]"
    assert out[0]["meta"] == {"x": 1}
    assert count == 1


@pytest.mark.parametrize("key", ["passport_number", "PASSPORT_NUMBER", "Passport_Number"])
def test_field_names_are_case_insensitive(r, key):
    # A bare 9-digit value has no regex match, so only the field rule can catch it.
    assert r.redact({key: "575977079"})[0][key] == "[PASSPORT_1]"


def test_none_under_sensitive_key_is_left_alone(r):
    assert r.redact({"ssn": None}) == ({"ssn": None}, 0)


@pytest.mark.parametrize("value", [123456789, 1234567890, 12.5])
def test_non_string_value_under_sensitive_key_is_redacted(r, value):
    out, count = r.redact({"ssn": value})
    assert out == {"ssn": "[SSN_1]"} and count == 1


@pytest.mark.parametrize("bad", [b"bytes", {1, 2}, object()])
def test_unsupported_types_fail_closed(r, bad):
    with pytest.raises(RedactionError):
        r.redact(bad)
    with pytest.raises(RedactionError):
        r.redact({"ok": "fine", "nested": [bad]})
    with pytest.raises(RedactionError):  # also under a sensitive key: must not pass through
        r.redact({"ssn": bad})
    with pytest.raises(RedactionError):
        r.redact({"mrz": [bad]})


# ---------------------------------------------------------------------------- field pass


@pytest.mark.parametrize(
    "key, value, label",
    [
        ("ssn", "048-35-9117", "SSN"),
        ("passport_number", "575977079", "PASSPORT"),
        ("email", "newmantimothy@example.com", "EMAIL"),
        ("phone", "2923281520", "PHONE"),
        ("dob", "1951-06-20", "DOB"),
        ("name", "Tammy Alexander", "PERSON"),
        ("address", "8081 Matthew Station, Sandovalburgh, AR 10493", "ADDRESS"),
        ("place_of_birth", "New Emilyhaven, OR", "LOCATION"),
    ],
)
def test_each_sensitive_field_is_redacted(r, key, value, label):
    assert r.redact({key: value}) == ({key: f"[{label}_1]"}, 1)


def test_list_under_sensitive_key_redacts_every_element(r):
    mrz = ["P<USAALEXANDER<<TAMMY<<<<<<<<<<<<<<<<<<<<<<<", "V11530005<0USA5106200M3504180<<<<<<<<<<<<<<<"]
    out, count = r.redact({"mrz": mrz})
    assert out == {"mrz": ["[MRZ_1]", "[MRZ_2]"]}
    assert count == 2


def test_non_sensitive_fields_are_preserved_exactly(r):
    record = {
        "traveler_id": "T1000",
        "nationality": "USA",
        "sex": "F",
        "issue_date": "2025-04-16",
        "expiry_date": "2035-04-16",
        "visa_history": [{"country": "Luxembourg", "visa_type": "F1", "expires": "2027-01-20"}],
        "ssn": "048-35-9117",
    }
    out, count = r.redact(record)
    assert count == 1
    assert {k: v for k, v in out.items() if k != "ssn"} == {k: v for k, v in record.items() if k != "ssn"}


# --------------------------------------------------------------------------- regex pass


@pytest.mark.parametrize("text", ["SSN on file 284-85-0659.", "ssn 284 85 0659 on file", "(284-85-0659)"])
def test_ssn_in_free_text(r, text):
    out, count = r.redact(text)
    assert "284" not in out and "[SSN_1]" in out and count == 1


@pytest.mark.parametrize(
    "email",
    ["ellen@example.com", "ellen.gibson+tag@sub.example.co.uk", "ELLEN@EXAMPLE.COM", "e_g-1@x.org"],
)
def test_email_in_free_text(r, email):
    out, count = r.redact(f"Confirmation emailed to {email}, thanks")
    assert out == "Confirmation emailed to [EMAIL_1], thanks" and count == 1


@pytest.mark.parametrize(
    "phone",
    [
        "+1-397-997-2121x0873",
        "(878)374-4126",
        "240.559.4189",
        "001-928-286-5289x899",
        "(348)956-8397x7578",
        "(770)986-1113x67634",
        "930.666.7659x839",
        "759-632-0497x0626",
    ],
)
def test_every_faker_phone_format_in_free_text(r, phone):
    assert r.redact(f"called from {phone} today") == ("called from [PHONE_1] today", 1)


def test_trailing_punctuation_is_not_swallowed(r):
    assert r.redact("Call 240.559.4189.") == ("Call [PHONE_1].", 1)
    assert r.redact("Email a@example.com, then stop") == ("Email [EMAIL_1], then stop", 1)


def test_mrz_lines_in_free_text(r):
    line1 = "P<USAALEXANDER<<TAMMY<<<<<<<<<<<<<<<<<<<<<<<"
    line2 = "V11530005<0USA5106200M3504180<<<<<<<<<<<<<<<"
    out, count = r.redact(f"MRZ was {line1} and {line2}.")
    assert out == "MRZ was [MRZ_1] and [MRZ_2]." and count == 2


def test_passport_pattern_in_free_text(r):
    assert r.redact("renew passport V11530005 soon") == ("renew passport [PASSPORT_1] soon", 1)


def test_multiple_kinds_in_one_string(r):
    out, count = r.redact("a@example.com / 284-85-0659 / 240.559.4189")
    assert out == "[EMAIL_1] / [SSN_1] / [PHONE_1]" and count == 3


@pytest.mark.parametrize(
    "text",
    [
        "Booking ref BK-4821-7731 confirmed",
        "Order 123456789 shipped",  # bare 9 digits: indistinguishable from an order number
        "Call back on 2923281520",  # bare 10 digits: same
        "Tracking 1Z999AA10123456784",
        "Meeting 10:30-11:45 tomorrow",
        "ISO date 2024-01-15 and 2026-10-03",
        "Version 3.12.1 released",
        "Invoice #555-1234 is overdue",
        "Flight UA 1234 departs 2026-10-03",
        "Zip 20742-1234",
        "Ping @alice about it",
        "Total $1,234.56 due",
        "Ref A1234567890 and B12345",  # letter + wrong digit count must not look like a passport
    ],
)
def test_lookalikes_are_not_redacted(r, text):
    assert r.redact(text) == (text, 0)


# ------------------------------------------------------- known-value propagation


def test_known_name_is_redacted_in_free_text_regardless_of_key_order(r):
    record = {
        "notes": "Tammy Alexander called about a refund.",
        "name": "Tammy Alexander",
    }
    out, count = r.redact(record)
    assert out == {"notes": "[PERSON_1] called about a refund.", "name": "[PERSON_1]"}
    assert count == 2


def test_bare_numbers_are_caught_when_known_from_structured_fields(r):
    record = {
        "passport_number": "575977079",
        "phone": "2923281520",
        "notes": "Renew passport 575977079; call 2923281520.",
    }
    out, count = r.redact(record)
    assert out["notes"] == "Renew passport [PASSPORT_1]; call [PHONE_1]."
    assert count == 4


def test_known_values_persist_across_calls_on_one_instance(r):
    r.redact({"name": "Tammy Alexander"})
    assert r.redact("Tammy Alexander asked for a refund") == ("[PERSON_1] asked for a refund", 1)


def test_known_value_match_is_case_insensitive(r):
    r.redact({"name": "Tammy Alexander"})
    assert r.redact("NO RECORD FOR TAMMY ALEXANDER") == ("NO RECORD FOR [PERSON_1]", 1)


def test_known_value_must_match_whole_token(r):
    r.redact({"name": "Tammy Alexander"})
    text = "Tammy Alexanderson is a different person"
    assert r.redact(text) == (text, 0)


def test_short_known_values_are_not_propagated(r):
    # "Al" is a whole token in the note, so only the length rule keeps it intact.
    out, count = r.redact({"name": "Al", "notes": "Al went to Alabama"})
    assert out == {"name": "[PERSON_1]", "notes": "Al went to Alabama"}
    assert count == 1


def test_unknown_names_are_a_documented_limitation(r):
    text = "Spoke with Jordan Rivera yesterday"
    assert r.redact(text) == (text, 0)


# ------------------------------------------------------------------------ placeholders


def test_same_value_gets_same_placeholder(r):
    out, count = r.redact({"a": "x 284-85-0659 y", "b": "again 284-85-0659"})
    assert out == {"a": "x [SSN_1] y", "b": "again [SSN_1]"}
    assert count == 2


def test_different_values_are_numbered_per_label_in_first_seen_order(r):
    out, _ = r.redact("284-85-0659, a@x.com, 111-22-3333, b@x.com, 284-85-0659")
    assert out == "[SSN_1], [EMAIL_1], [SSN_2], [EMAIL_2], [SSN_1]"


def test_same_email_in_different_case_is_one_entity(r):
    out, _ = r.redact("Bob@Example.COM then bob@example.com")
    assert out == "[EMAIL_1] then [EMAIL_1]"


def test_field_pass_and_regex_pass_share_a_placeholder(r):
    out, count = r.redact({"ssn": "048-35-9117", "notes": "SSN 048-35-9117"})
    assert out == {"ssn": "[SSN_1]", "notes": "SSN [SSN_1]"}
    assert count == 2


def test_placeholders_are_stable_across_calls(r):
    assert r.redact("284-85-0659")[0] == "[SSN_1]"
    assert r.redact("111-22-3333 and 284-85-0659")[0] == "[SSN_2] and [SSN_1]"


def test_new_instance_restarts_numbering():
    a, b = fresh(), fresh()
    a.redact("111-22-3333")
    assert a.redact("284-85-0659")[0] == "[SSN_2]"
    assert b.redact("284-85-0659")[0] == "[SSN_1]"


def test_new_instance_has_no_known_values():
    a, b = fresh(), fresh()
    a.redact({"name": "Tammy Alexander"})
    text = "Tammy Alexander asked for a refund"
    assert b.redact(text) == (text, 0)


def test_placeholder_format(r):
    out, _ = r.redact({"ssn": "048-35-9117", "name": "Tammy Alexander", "email": "a@example.com"})
    assert all(PLACEHOLDER.match(v) for v in out.values())


def test_redaction_is_idempotent(r):
    once, first = r.redact({"ssn": "048-35-9117", "notes": "call 240.559.4189 re 284-85-0659"})
    twice, second = r.redact(once)
    assert twice == once and first == 3 and second == 0


# ----------------------------------------------------------------- error-message leaks


def test_pii_in_error_text_is_redacted(r):
    out, count = r.redact("Error: no match for 048-35-9117 (contact ellen@example.com)")
    assert out == "Error: no match for [SSN_1] (contact [EMAIL_1])" and count == 2


# --------------------------------------------- golden: the real fake_passport records


def _raw_sensitive_values(t: dict) -> list[str]:
    given, surname = t["name"].split(" ", 1)
    return [
        t["name"], given, surname, t["passport_number"], t["ssn"], t["email"], t["phone"],
        t["dob"], t["address"], t["place_of_birth"], *t["mrz"],
    ]  # fmt: skip


def assert_no_leak(output, record: dict) -> None:
    dumped = json.dumps(output)
    for raw in _raw_sensitive_values(record):
        assert raw not in dumped, f"leaked {raw!r}"
        assert raw.upper() not in dumped.upper(), f"leaked (case-folded) {raw!r}"
    # Values that only appear in the free-text note and are only catchable by pattern:
    assert "@" not in dumped, "an email survived"
    assert not re.search(r"\d{3}-\d{2}-\d{4}", dumped), "an SSN survived"


@pytest.mark.parametrize("record", TRAVELERS, ids=[t["traveler_id"] for t in TRAVELERS])
def test_golden_no_raw_pii_survives(record):
    out, count = fresh().redact(record)
    assert_no_leak(out, record)
    # 8 sensitive scalar fields + 2 mrz lines + 5 in the note (name, phone, passport, email, ssn)
    assert count == 15


@pytest.mark.parametrize("record", TRAVELERS, ids=[t["traveler_id"] for t in TRAVELERS])
def test_golden_non_sensitive_fields_survive(record):
    out, _ = fresh().redact(record)
    for key in ("traveler_id", "nationality", "sex", "issue_date", "expiry_date", "visa_history"):
        assert out[key] == record[key]


def test_golden_one_session_keeps_travelers_distinct():
    r = fresh()
    outs = [r.redact(t)[0] for t in TRAVELERS]
    for out, t in zip(outs, TRAVELERS, strict=True):
        assert_no_leak(out, t)
    assert len({o["name"] for o in outs}) == len(TRAVELERS)
    assert len({o["ssn"] for o in outs}) == len(TRAVELERS)


def test_golden_note_mentions_map_to_the_structured_placeholders():
    out, _ = fresh().redact(TRAVELERS[0])
    assert out["name"] in out["notes"]
    assert out["phone"] in out["notes"]
    assert out["passport_number"] in out["notes"]
    # the note also contains a *different* SSN and email, found only by pattern
    assert "[SSN_2]" in out["notes"] and "[EMAIL_2]" in out["notes"]
