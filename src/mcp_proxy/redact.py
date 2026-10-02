"""Redaction of sensitive data in tool results (phase 2).

Planned approach:
  1. Walk the JSON structure and redact by field name (ssn, dob, phone, ...).
  2. Run regex over remaining free-text strings.
  3. Use stable per-session placeholders ([PERSON_1], [SSN_1]) so the model can
     still tell two mentions are the same entity.
  4. Keep the rule set pluggable so Presidio can replace it later.
Must fail closed: if redaction raises, the proxy returns an error, never the raw result.
"""

from __future__ import annotations

from typing import Any, Protocol


class Redactor(Protocol):
    def redact(self, value: Any) -> tuple[Any, int]:
        """Return (redacted_value, number_of_redactions)."""
        ...
