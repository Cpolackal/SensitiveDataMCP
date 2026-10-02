import pytest

# Use the in-memory transport: Client(build_proxy(fake_ehr, audit)).
# from fake_ehr.server import mcp as fake_ehr

pytestmark = pytest.mark.skip(reason="skeleton: implement proxy first")


async def test_lists_upstream_tools():
    ...


async def test_call_is_forwarded_and_logged():
    ...


async def test_upstream_error_is_logged():
    ...
