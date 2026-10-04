from pathlib import Path

import pytest

from mcp_proxy.config import load_config

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def example_redaction():
    """The redaction rules shipped in config.example.yaml (so the example is tested too)."""
    return load_config(ROOT / "config.example.yaml").redaction
