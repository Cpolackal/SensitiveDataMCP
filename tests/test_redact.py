import pytest

pytestmark = pytest.mark.skip(reason="skeleton: phase 2")

# Ideas: table-driven known PII; no raw value anywhere in output (nested + free text);
# false positives (booking reference that looks like a passport number); PII in error messages
# and structuredContent; fail-closed when redaction raises.
