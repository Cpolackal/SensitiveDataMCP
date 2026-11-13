"""Redaction of sensitive data in tool results.

Approach (the contract is pinned down in tests/test_redact.py):
  1. Field pass: the value under a sensitive key is replaced wholesale.
  2. Regex pass: pattern matches inside any string are replaced, dict keys included (APIs
     key maps by email or name). Keys that would collide once redacted fail closed.
  3. Known-value propagation: a string seen under a sensitive key is remembered and also
     replaced wherever it appears in free text (this catches names and bare digit runs
     that no regex can).
  4. Placeholders ([PERSON_1], [SSN_2]) are stable per instance, so the model can still
     tell that two mentions are the same entity. One instance == one session.
  5. A string that is itself a JSON object or array (a stringified payload) is parsed and
     handled as a structure, at any depth, so passes 1-3 apply inside it too.
Fails closed: anything that is not JSON-like raises RedactionError, so the proxy returns an
error instead of the raw result. The rule set is pluggable: any object with a matching
`redact` method (e.g. a Presidio-backed one) can replace FieldRegexRedactor.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

# Known values shorter than this are not propagated into free text: they would corrupt
# unrelated text ("Al", "OR") far more often than they would catch a leak.
MIN_KNOWN_VALUE_LEN = 4

_LABEL = re.compile(r"[A-Z]+")
_PLACEHOLDER = re.compile(r"\[[A-Z]+_\d+\]")


def _as_json_container(text: str) -> dict | list | None:
    """The parsed value if `text` is a JSON object or array, else None. Cheap check first:
    most strings are prose, and json.loads on them is wasted work."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        parsed = json.loads(stripped)
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


class Redactor(Protocol):
    def redact(self, value: Any) -> tuple[Any, int]:
        """Return (redacted_value, number_of_redactions)."""
        ...


class RedactionError(Exception):
    """The value could not be redacted safely. Callers must not fall back to the raw value."""


@dataclass
class _Run:
    """Per-call counter, so redact() holds no mutable per-call state on the instance."""

    count: int = 0


class FieldRegexRedactor:
    """Field-name + regex + known-value redaction with stable placeholders.

    `fields` maps a JSON key (matched case-insensitively) to a label, e.g. {"ssn": "SSN"}.
    `patterns` maps a label to a regex applied to free text. Labels must be A-Z only so
    placeholders stay recognisable (and therefore idempotent).

    Not thread-safe across concurrent redact() calls on one instance; redact() never
    awaits, so it is atomic under asyncio.
    """

    def __init__(self, fields: dict[str, str], patterns: dict[str, str]) -> None:
        for label in (*fields.values(), *patterns):
            if not _LABEL.fullmatch(label):
                raise ValueError(f"label {label!r} must match [A-Z]+")
        self._fields = {name.lower(): label for name, label in fields.items()}
        self._patterns: list[tuple[str, re.Pattern[str]]] = []
        for label, pattern in patterns.items():
            try:
                self._patterns.append((label, re.compile(pattern)))
            except re.error as exc:
                raise ValueError(f"invalid pattern for {label}: {exc}") from exc

        self._placeholders: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}
        # casefolded known value -> (label, original text); the regex is rebuilt lazily.
        self._known: dict[str, tuple[str, str]] = {}
        self._known_regex: re.Pattern[str] | None = None

    # ------------------------------------------------------------------ public API

    def redact(self, value: Any) -> tuple[Any, int]:
        run = _Run()
        self._learn(value, None, "$")  # first, so sibling keys in any order are covered
        return self._walk(value, run, "$"), run.count

    # ---------------------------------------------------------------- placeholders

    def _placeholder(self, label: str, raw: str) -> str:
        key = (label, raw.strip().casefold())
        placeholder = self._placeholders.get(key)
        if placeholder is None:
            n = self._counters[label] = self._counters.get(label, 0) + 1
            placeholder = self._placeholders[key] = f"[{label}_{n}]"
        return placeholder

    # ------------------------------------------------------------------- learning

    def _learn(self, node: Any, label: str | None, path: str) -> None:
        """Remember strings found under sensitive keys (leaves of any nesting)."""
        if isinstance(node, dict):
            for key, child in node.items():
                child_label = self._fields.get(key.lower()) if isinstance(key, str) else None
                self._learn(child, child_label, f"{path}.{key}")
        elif isinstance(node, list):
            for i, child in enumerate(node):
                self._learn(child, label, f"{path}[{i}]")
        elif label is None and isinstance(node, str):
            # A stringified payload can hold sensitive keys of its own.
            parsed = _as_json_container(node)
            if parsed is not None:
                self._learn(parsed, None, f"{path}<json>")
        elif label is not None:
            if isinstance(node, int) and not isinstance(node, bool):
                node = str(node)
            if isinstance(node, str):
                text = node.strip()
                if len(text) >= MIN_KNOWN_VALUE_LEN and not _PLACEHOLDER.fullmatch(text):
                    key = text.casefold()
                    if key not in self._known:
                        self._known[key] = (label, text)
                        self._known_regex = None

    def _known_pattern(self) -> re.Pattern[str] | None:
        if self._known_regex is None and self._known:
            # Longest first so "Tammy Alexander" wins over any shorter known value inside it.
            texts = sorted((text for _, text in self._known.values()), key=len, reverse=True)
            alternation = "|".join(re.escape(t) for t in texts)
            self._known_regex = re.compile(rf"(?<!\w)(?:{alternation})(?!\w)", re.IGNORECASE)
        return self._known_regex

    # -------------------------------------------------------------------- walking

    def _key(self, out: dict, key: Any, run: _Run, path: str) -> Any:
        """Redacted copy of a dict key, for storing into `out`. Keys get the free-text pass,
        since APIs key maps by email, name or id. Two keys that redact to the same text (one
        email in two cases) would silently drop a value, so that fails closed instead.
        Called before the value is walked, so placeholder numbering stays first-seen."""
        safe_key = self._text(key, run) if isinstance(key, str) else key
        if safe_key in out:
            raise RedactionError(f"redacted keys collide at {path}")
        return safe_key

    def _walk(self, node: Any, run: _Run, path: str) -> Any:
        if isinstance(node, dict):
            out: dict = {}
            for key, child in node.items():
                # The field rule matches the original key, before the key itself is redacted.
                label = self._fields.get(key.lower()) if isinstance(key, str) else None
                child_path = f"{path}.{key}"
                safe_key = self._key(out, key, run, path)
                out[safe_key] = (
                    self._field(child, label, run, child_path)
                    if label
                    else self._walk(child, run, child_path)
                )
            return out
        if isinstance(node, list):
            return [self._walk(child, run, f"{path}[{i}]") for i, child in enumerate(node)]
        if isinstance(node, str):
            return self._string(node, run, path)
        if isinstance(node, int) and not isinstance(node, bool):
            return self._int(node, run)
        if node is None or isinstance(node, (float, bool)):
            return node
        raise RedactionError(f"unsupported type {type(node).__name__} at {path}")

    def _field(self, node: Any, label: str, run: _Run, path: str) -> Any:
        """Redact everything under a sensitive key: every leaf becomes a placeholder."""
        if node is None:
            return None
        if isinstance(node, dict):
            out: dict = {}
            for k, v in node.items():
                safe_key = self._key(out, k, run, path)
                out[safe_key] = self._field(v, label, run, f"{path}.{k}")
            return out
        if isinstance(node, list):
            return [self._field(v, label, run, f"{path}[{i}]") for i, v in enumerate(node)]
        if isinstance(node, str) and _PLACEHOLDER.fullmatch(node):
            return node  # already redacted: keeps redact() idempotent
        if isinstance(node, (str, int, float, bool)):
            run.count += 1
            return self._placeholder(label, str(node))
        raise RedactionError(f"unsupported type {type(node).__name__} at {path}")

    def _string(self, text: str, run: _Run, path: str) -> str:
        """A JSON object/array string is walked as a structure and re-serialized; anything
        else gets the free-text pass. An untouched payload is returned byte-for-byte, so
        redaction never reformats data it didn't change."""
        parsed = _as_json_container(text)
        if parsed is None:
            return self._text(text, run)
        inner = _Run()
        redacted = self._walk(parsed, inner, f"{path}<json>")
        if inner.count == 0:
            return text
        run.count += inner.count
        return json.dumps(redacted, ensure_ascii=False)

    def _int(self, value: int, run: _Run) -> int | str:
        """An int outside a sensitive field that equals a known value (a passport number
        stored as a number elsewhere) becomes its placeholder; the type changes, which is
        the safe direction. Whole-value match only: digits inside a larger int are not
        matched, and regex patterns are not applied (they all need separators)."""
        known = self._known.get(str(value))
        if known is None:
            return value
        run.count += 1
        return self._placeholder(known[0], known[1])

    def _text(self, text: str, run: _Run) -> str:
        # (start, end, label, matched). Known values are listed first so that, on an
        # identical span, the label the data was declared under beats a regex label.
        spans: list[tuple[int, int, str, str]] = []
        known = self._known_pattern()
        if known is not None:
            for m in known.finditer(text):
                label, _ = self._known[m.group().casefold()]
                spans.append((m.start(), m.end(), label, m.group()))
        for label, pattern in self._patterns:
            for m in pattern.finditer(text):
                if m.end() > m.start():
                    spans.append((m.start(), m.end(), label, m.group()))
        if not spans:
            return text

        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))  # stable: leftmost, then longest
        # Merge overlapping spans rather than dropping the later one: dropping it would leave
        # the part that sticks out past the earlier span in plain text. The merged span keeps
        # the leftmost-longest span's label; a span that merged nothing keeps its own match,
        # so its placeholder is shared with other mentions of the same value.
        merged: list[list] = []  # [start, end, label, matched or None once merged]
        for start, end, label, matched in spans:
            if merged and start < merged[-1][1]:
                if end > merged[-1][1]:
                    merged[-1][1] = end
                    merged[-1][3] = None
            else:
                merged.append([start, end, label, matched])

        pieces: list[str] = []
        cursor = 0
        for start, end, label, matched in merged:
            pieces.append(text[cursor:start])
            # Minted left to right so numbering is first-seen order.
            pieces.append(self._placeholder(label, matched or text[start:end]))
            cursor = end
        pieces.append(text[cursor:])
        run.count += len(merged)
        return "".join(pieces)
