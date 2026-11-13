"""Edge cases for FieldRegexRedactor, run against the rules shipped in config.example.yaml.

Three groups:
  * Core behavior not pinned down elsewhere (these pass today).
  * Known gaps, marked `xfail(strict=True)`. Each one documents something the redactor
    misses today. Strict means the suite fails as soon as a fix lands, so the marker has to
    be removed and the test then guards the fix.
      - STRUCTURAL: the engine's own logic misses data it could catch.
      - INTEGRITY: nothing leaks, but placeholders mislead the model about identity.
      - LIMITATION: needs normalization or NER beyond field/regex/known-value matching.
"""

from __future__ import annotations

import json

import pytest

from mcp_proxy.redact import FieldRegexRedactor, RedactionError

SEED = {
    "name": "Gregory Moore",
    "passport_number": "575977079",
    "ssn": "242-47-3361",
    "email": "janetclay@example.net",
    "phone": "(878)374-4126",
}


@pytest.fixture
def r(example_redaction):
    return example_redaction.make_redactor()


@pytest.fixture
def seeded(r):
    """A redactor that has already seen SEED, so its values are known for propagation."""
    r.redact(SEED)
    return r


def dump(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def structural(reason: str):
    return pytest.mark.xfail(strict=True, reason=f"STRUCTURAL: {reason}")


def integrity(reason: str):
    return pytest.mark.xfail(strict=True, reason=f"INTEGRITY: {reason}")


def limitation(reason: str):
    return pytest.mark.xfail(strict=True, reason=f"LIMITATION: {reason}")


# ------------------------------------------------------------- core behavior (passing)


def test_same_start_overlap_picks_the_longest_match():
    r = FieldRegexRedactor({}, {"SHORT": r"AB\d", "LONG": r"AB\d{3}"})
    assert r.redact("x AB123 y") == ("x [LONG_1] y", 1)


def test_known_value_label_beats_regex_label_on_the_same_span():
    r = FieldRegexRedactor(
        {"backup_contact": "CONTACT"},
        {"EMAIL": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"},
    )
    out, _ = r.redact({"backup_contact": "a.b@example.com", "notes": "write to a.b@example.com"})
    assert out["notes"] == "write to [CONTACT_1]"


def test_known_value_at_the_minimum_length_is_propagated(r):
    out, _ = r.redact({"name": "Abby", "notes": "Abby called"})
    assert out["notes"] == "[PERSON_1] called"


def test_int_under_a_sensitive_key_is_learned_and_caught_in_text(r):
    out, _ = r.redact({"passport_number": 575977079, "notes": "renewing 575977079 today"})
    assert out["passport_number"] == "[PASSPORT_1]"
    assert out["notes"] == "renewing [PASSPORT_1] today"


def test_every_value_in_a_list_under_a_sensitive_key_is_learned(r):
    out, _ = r.redact({"name": ["Ann Leeson", "Bob Rayburn"], "notes": "Bob Rayburn met Ann Leeson"})
    assert out["name"] == ["[PERSON_1]", "[PERSON_2]"]
    assert out["notes"] == "[PERSON_2] met [PERSON_1]"


def test_placeholders_in_free_text_are_left_alone_and_not_counted(r):
    assert r.redact("see [PERSON_1] and [SSN_3]") == ("see [PERSON_1] and [SSN_3]", 0)


def test_count_is_the_number_of_placeholders_inserted(r):
    out, n = r.redact({**SEED, "notes": "Gregory Moore, 242-47-3361, janetclay@example.net"})
    assert n == dump(out).count("[") == 8


def test_values_learned_in_one_call_cover_free_text_in_the_next(seeded):
    out, n = seeded.redact("Gregory Moore's passport 575977079")
    assert (out, n) == ("[PERSON_1]'s passport [PASSPORT_1]", 2)


def test_no_seed_value_survives_a_mixed_record(r):
    record = {
        **SEED,
        "history": [{"note": f"{SEED['name']} at {SEED['phone']}"}, SEED["email"]],
        "deep": {"x": {"y": [f"passport {SEED['passport_number']} / ssn {SEED['ssn']}"]}},
    }
    seen = dump(r.redact(record)[0])
    for raw in SEED.values():
        assert raw not in seen


# --------------------------------------------------------------------------- dict keys


def test_regex_pii_used_as_a_dict_key_is_redacted(r):
    out, n = r.redact({"by_email": {"janetclay@example.net": {"visits": 3}},
                       "by_ssn": {"242-47-3361": "ok"}})  # fmt: skip
    assert out == {"by_email": {"[EMAIL_1]": {"visits": 3}}, "by_ssn": {"[SSN_1]": "ok"}}
    assert n == 2


def test_known_name_used_as_a_dict_key_is_redacted(seeded):
    out, n = seeded.redact({"Gregory Moore": {"visits": 3}})
    assert (out, n) == ({"[PERSON_1]": {"visits": 3}}, 1)


def test_key_and_value_mentions_of_one_entity_share_a_placeholder(r):
    out, _ = r.redact({"name": "Gregory Moore", "visits": {"Gregory Moore": 3}})
    assert out == {"name": "[PERSON_1]", "visits": {"[PERSON_1]": 3}}


def test_field_rule_matches_the_original_key_and_key_is_redacted_first(r):
    # The key is minted before its value is walked, so numbering is first-seen.
    out, _ = r.redact({"a@example.com": {"email": "b@example.com"}})
    assert out == {"[EMAIL_1]": {"email": "[EMAIL_2]"}}


def test_pii_keys_under_a_sensitive_field_are_redacted_too(r):
    out, _ = r.redact({"phone": {"janetclay@example.net": "878-374-4126"}})
    assert out == {"phone": {"[EMAIL_1]": "[PHONE_1]"}}


def test_keys_that_redact_to_the_same_text_fail_closed(r):
    # One email in two cases is one entity, so both keys become [EMAIL_1]; keeping only one
    # value would silently drop data.
    with pytest.raises(RedactionError, match="collide"):
        r.redact({"janetclay@example.net": 1, "JanetClay@example.net": 2})


def test_redacting_keys_is_idempotent(r):
    once, _ = r.redact({"janetclay@example.net": {"242-47-3361": 1}})
    assert r.redact(once) == (once, 0)


# ------------------------------------------------------------------ ints as known values


def test_known_value_appearing_as_an_int_elsewhere_is_redacted(seeded):
    out, n = seeded.redact({"ref": 575977079, "refs": [1, 575977079]})
    assert out == {"ref": "[PASSPORT_1]", "refs": [1, "[PASSPORT_1]"]}
    assert n == 2


def test_int_learned_in_the_same_record_is_redacted_elsewhere(r):
    out, _ = r.redact({"passport_number": 575977079, "booking": {"doc": 575977079}})
    assert out == {"passport_number": "[PASSPORT_1]", "booking": {"doc": "[PASSPORT_1]"}}


@pytest.mark.parametrize("value", [1, 2024, 5759770790, -575977079, 0])
def test_ints_that_are_not_exactly_a_known_value_pass_through(seeded, value):
    assert seeded.redact({"n": value}) == ({"n": value}, 0)


def test_bools_and_floats_are_never_treated_as_known_ints(r):
    r.redact({"passport_number": "1111", "ssn": 1})  # "1" is too short to be learned anyway
    assert r.redact({"a": True, "b": 1111.0}) == ({"a": True, "b": 1111.0}, 0)


# ------------------------------------------------------------- JSON nested in strings


def test_json_string_nested_in_a_field_gets_field_rules(r):
    payload = json.dumps({"ssn": "242473361", "name": "Gregory Moore"})
    out, n = r.redact({"payload": payload})
    assert json.loads(out["payload"]) == {"ssn": "[SSN_1]", "name": "[PERSON_1]"}
    assert n == 2


def test_values_learned_inside_nested_json_cover_text_outside_it(r):
    # The note comes first, so this also checks learning happens before walking.
    record = {"note": "Gregory Moore called", "raw": json.dumps({"name": "Gregory Moore"})}
    out, _ = r.redact(record)
    assert out["note"] == "[PERSON_1] called"
    assert json.loads(out["raw"]) == {"name": "[PERSON_1]"}


def test_doubly_encoded_json_is_redacted(r):
    inner = json.dumps({"ssn": "242473361"})
    out, _ = r.redact({"envelope": json.dumps({"body": inner})})
    body = json.loads(json.loads(out["envelope"])["body"])
    assert body == {"ssn": "[SSN_1]"}


def test_json_array_string_is_parsed(r):
    out, _ = r.redact(json.dumps([{"email": "janetclay@example.net"}, "plain"]))
    assert json.loads(out) == [{"email": "[EMAIL_1]"}, "plain"]


def test_nested_json_with_nothing_to_redact_is_returned_byte_for_byte(r):
    payload = '{"status":"ok",  "count": 3}'
    assert r.redact({"payload": payload}) == ({"payload": payload}, 0)


@pytest.mark.parametrize("text", ['{"broken": ', "[not json", "{} trailing", '"just a string"', "42"])
def test_non_container_or_invalid_json_gets_the_free_text_pass(r, text):
    assert r.redact(f"{text} 242-47-3361") == (f"{text} [SSN_1]", 1)


def test_nested_json_redaction_is_idempotent(r):
    once, _ = r.redact({"payload": json.dumps({"ssn": "242473361"})})
    assert r.redact(once) == (once, 0)


# ------------------------------------------------------------------- STRUCTURAL gaps


@structural("a partially overlapping later match is dropped, leaving its tail visible")
def test_partially_overlapping_matches_leave_no_tail():
    r = FieldRegexRedactor({}, {"AAA": r"ID-\d{4}", "BBB": r"\d{2}-SECRET-\d{6}"})
    out, _ = r.redact("x ID-1234-SECRET-999999 y")
    assert "SECRET" not in out and "999999" not in out


# -------------------------------------------------------------------- INTEGRITY gaps


@integrity("placeholders key on the raw string, so one number in two formats is two entities")
def test_one_phone_number_in_two_formats_is_one_entity(seeded):
    out, _ = seeded.redact("Call 878-374-4126 or (878)374-4126")
    assert out == "Call [PHONE_1] or [PHONE_1]"


@integrity("an upstream string shaped like a placeholder collides with a real one")
def test_upstream_cannot_forge_a_placeholder(r):
    out, _ = r.redact({"ssn": "[SSN_1]", "notes": "real one is 242-47-3361"})
    assert out["notes"] != "real one is [SSN_1]"


# ------------------------------------------------------------------- LIMITATION gaps


@limitation("known names only match in full; a surname alone passes")
def test_surname_alone_is_redacted(seeded):
    out, _ = seeded.redact("Mr. Moore will call back")
    assert "Moore" not in out


@limitation("known names only match in the order they were seen")
def test_reordered_name_is_redacted(seeded):
    out, _ = seeded.redact("Moore, Gregory")
    assert "Gregory" not in out and "Moore" not in out


@limitation("known values match literal whitespace only")
@pytest.mark.parametrize("text", ["Gregory  Moore", "Gregory Moore", "Gregory\nMoore"])
def test_whitespace_variants_of_a_known_name_are_redacted(seeded, text):
    out, _ = seeded.redact(text)
    assert "Gregory" not in out


@limitation("known values match their exact format; a dashless SSN passes")
def test_known_ssn_without_dashes_is_redacted(seeded):
    out, _ = seeded.redact("SSN 242473361")
    assert "242473361" not in out


@limitation("field names match exactly; common spellings of the same field are missed")
@pytest.mark.parametrize(
    "key,value",
    [("phoneNumber", "8783744126"), ("passportNo", "575977079"), ("full_name", "Gregory Moore")],
)
def test_field_name_variants_are_redacted(r, key, value):
    out, _ = r.redact({key: value})
    assert out[key] != value


@limitation("no Unicode normalization: zero-width and fullwidth characters evade matching")
@pytest.mark.parametrize("text", ["SSN 242​-47-3361", "ＧＲＥＧＯＲＹ ＭＯＯＲＥ"])
def test_unicode_obfuscation_is_redacted(seeded, text):
    out, n = seeded.redact(text)
    assert n == 1, out
