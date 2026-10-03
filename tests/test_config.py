import pytest

from mcp_proxy.config import ConfigError, load_config


def write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return p


def test_loads_minimal_config(tmp_path):
    cfg = load_config(write(tmp_path, "upstream:\n  command: python\n"))
    assert cfg.upstream.command == "python"
    assert cfg.upstream.args == []
    assert cfg.audit_db == tmp_path / "audit.sqlite"


def test_loads_full_config(tmp_path):
    cfg = load_config(
        write(
            tmp_path,
            "upstream:\n  command: uv\n  args: [run, server.py]\n  env: {A: b}\n"
            "log:\n  db: logs/a.sqlite\n",
        )
    )
    assert cfg.upstream.args == ["run", "server.py"]
    assert cfg.upstream.env == {"A": "b"}
    assert cfg.audit_db == tmp_path / "logs" / "a.sqlite"


def test_relative_paths_resolve_against_config_dir_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir("/")
    cfg = load_config(write(tmp_path, "upstream:\n  command: x\n"))
    assert cfg.upstream.cwd == tmp_path
    assert cfg.audit_db.parent == tmp_path


def test_absolute_db_path_is_kept(tmp_path):
    cfg = load_config(write(tmp_path, "upstream:\n  command: x\nlog:\n  db: /var/a.sqlite\n"))
    assert str(cfg.audit_db) == "/var/a.sqlite"


@pytest.mark.parametrize(
    "text, match",
    [
        ("", "mapping"),
        ("- a\n- b\n", "mapping"),
        ("log:\n  db: a\n", "upstream"),
        ("upstream:\n  args: [a]\n", "command"),
        ("upstream:\n  command: ''\n", "command"),
        ("upstream:\n  command: x\n  args: nope\n", "args"),
        ("upstream:\n  command: x\n  env: [a]\n", "env"),
        ("upstream:\n  command: x\nlog: nope\n", "log"),
        ("upstream: [unclosed\n", "invalid YAML"),
    ],
)
def test_invalid_config_raises_clear_error(tmp_path, text, match):
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, text))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")
