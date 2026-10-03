"""End-to-end over real stdio: test client -> proxy subprocess -> fake_passport subprocess."""

import subprocess
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent


def _proxy_params(config: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_proxy.server", "--config", str(config)],
        env={"PYTHONPATH": str(ROOT / "src")},
    )


def _write_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"upstream:\n  command: {sys.executable}\n"
        f"  args: [{ROOT / 'fake_passport' / 'server.py'}]\n"
    )
    return cfg


async def test_proxy_over_stdio(tmp_path):
    async with Client(_proxy_params(_write_config(tmp_path))) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert {"search_travelers", "get_passport", "get_visa_history"} <= tools
        res = await client.call_tool("search_travelers", {"query": ""})
    assert not res.is_error
    assert len(res.structured_content["result"]) == 10


def test_bad_config_exits_cleanly_without_touching_stdout(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_proxy.server", "--config", str(tmp_path / "nope.yaml")],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src")},
        timeout=30,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""  # stdout is the protocol channel
    assert "not found" in proc.stderr
