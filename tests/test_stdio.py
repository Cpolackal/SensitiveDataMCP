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


def _write_config(tmp_path: Path, redact: bool = True) -> Path:
    """Config for the fake server, reusing the redaction rules from config.example.yaml."""
    example = (ROOT / "config.example.yaml").read_text()
    redaction = example[example.index("\nredaction:\n") + 1 :] if redact else "redaction:\n  enabled: false\n"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"upstream:\n  command: {sys.executable}\n"
        f"  args: [{ROOT / 'fake_passport' / 'server.py'}]\n\n" + redaction
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


async def test_calls_over_stdio_are_written_to_the_audit_db(tmp_path):
    from mcp_proxy.audit import AuditLog

    cfg = _write_config(tmp_path)
    async with Client(_proxy_params(cfg)) as client:
        await client.call_tool("get_visa_history", {"traveler_id": "T1000"})

    # log.db defaults to audit.sqlite next to the config file
    audit = AuditLog(tmp_path / "audit.sqlite")
    (row,) = audit.query_calls()
    assert row["tool"] == "get_visa_history"
    assert audit.list_sessions()[0]["upstream"] == "fake-passport"
    audit.close()


async def test_redaction_over_stdio_end_to_end(tmp_path):
    import hashlib
    import json

    from fake_passport.server import TRAVELERS
    from mcp_proxy.audit import AuditLog

    record = TRAVELERS[1]
    async with Client(_proxy_params(_write_config(tmp_path))) as client:
        res = await client.call_tool("get_passport", {"traveler_id": record["traveler_id"]})

    seen = res.model_dump_json()  # everything the model could read
    for raw in (record["name"], record["ssn"], record["passport_number"], record["email"],
                record["phone"], record["address"]):
        assert raw not in seen, f"leaked {raw!r}"
    # get_passport returns `dict`, so its only copy is the JSON text block, which must be parsed
    shown = json.loads(res.content[0].text)
    assert shown["ssn"] == "[SSN_1]" and shown["traveler_id"] == record["traveler_id"]

    audit = AuditLog(tmp_path / "audit.sqlite")
    (row,) = audit.query_calls()
    assert record["ssn"] not in row["result_redacted"]
    assert row["redactions_count"] == 15
    # the stored hash is of the raw result, so it differs from a hash of what was stored
    assert row["result_sha256"] != hashlib.sha256(row["result_redacted"].encode()).hexdigest()
    audit.close()


def test_missing_redaction_section_is_refused_at_startup(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("upstream:\n  command: x\n")
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_proxy.server", "--config", str(cfg)],
        capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src")}, timeout=30,
    )
    assert proc.returncode == 2 and proc.stdout == ""
    assert "`redaction` is required" in proc.stderr
