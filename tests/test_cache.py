import pytest

pytestmark = pytest.mark.skip(reason="skeleton: phase 3")

# Ideas: repeated allowlisted call is a hit; non-allowlisted never cached;
# cached value is the redacted one; TTL expiry; key canonicalization of args.
