import pytest

pytestmark = pytest.mark.skip(reason="skeleton: phase 2")

# Ideas: table-driven known PHI; no raw value anywhere in output (nested + free text);
# false positives (order id that looks like a phone number); PHI in error messages
# and structuredContent; fail-closed when redaction raises.
