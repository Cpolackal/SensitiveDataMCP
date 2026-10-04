import pytest

from mcp_proxy.config import ConfigError, load_config


NO_REDACTION = "redaction:\n  enabled: false\n"


def write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return p


def test_loads_minimal_config(tmp_path):
    cfg = load_config(write(tmp_path, "upstream:\n  command: python\n" + NO_REDACTION))
    assert cfg.upstream.command == "python"
    assert cfg.upstream.args == []
    assert cfg.audit_db == tmp_path / "audit.sqlite"


def test_loads_full_config(tmp_path):
    cfg = load_config(
        write(
            tmp_path,
            "upstream:\n  command: uv\n  args: [run, server.py]\n  env: {A: b}\n"
            "log:\n  db: logs/a.sqlite\n" + NO_REDACTION,
        )
    )
    assert cfg.upstream.args == ["run", "server.py"]
    assert cfg.upstream.env == {"A": "b"}
    assert cfg.audit_db == tmp_path / "logs" / "a.sqlite"


def test_relative_paths_resolve_against_config_dir_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir("/")
    cfg = load_config(write(tmp_path, "upstream:\n  command: x\n" + NO_REDACTION))
    assert cfg.upstream.cwd == tmp_path
    assert cfg.audit_db.parent == tmp_path


def test_absolute_db_path_is_kept(tmp_path):
    cfg = load_config(write(tmp_path, "upstream:\n  command: x\nlog:\n  db: /var/a.sqlite\n" + NO_REDACTION))
    assert str(cfg.audit_db) == "/var/a.sqlite"


@pytest.mark.parametrize(
    "text, match",
    [
        ("", "mapping"),
        ("- a\n- b\n", "mapping"),
        ("log:\n  db: a\n", "upstream"),
        ("upstream:\n  args: [a]\n", "command"),
        ("upstream:\n  command: ''\n", "command"),
        ("upstream:\n  command: x\n  args: nope\n" + NO_REDACTION, "args"),
        ("upstream:\n  command: x\n  env: [a]\n" + NO_REDACTION, "env"),
        ("upstream:\n  command: x\nlog: nope\n" + NO_REDACTION, "log"),
        ("upstream: [unclosed\n", "invalid YAML"),
    ],
)
def test_invalid_config_raises_clear_error(tmp_path, text, match):
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, text))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


# ----------------------------------------------------------------------------- redaction

UP = "upstream:\n  command: x\n"


def test_redaction_section_is_required(tmp_path):
    with pytest.raises(ConfigError, match="`redaction` is required"):
        load_config(write(tmp_path, UP))


def test_redaction_can_be_explicitly_disabled(tmp_path):
    cfg = load_config(write(tmp_path, UP + NO_REDACTION))
    assert cfg.redaction.enabled is False
    assert cfg.redaction.make_redactor() is None


def test_redaction_rules_are_parsed(tmp_path):
    cfg = load_config(
        write(tmp_path, UP + "redaction:\n  fields: {ssn: SSN}\n  patterns: {SSN: '\\d{3}-\\d{2}-\\d{4}'}\n")
    )
    assert cfg.redaction.enabled and cfg.redaction.fields == {"ssn": "SSN"}
    assert cfg.redaction.patterns == {"SSN": r"\d{3}-\d{2}-\d{4}"}
    assert cfg.redaction.make_redactor().redact({"ssn": "123-45-6789"}) == ({"ssn": "[SSN_1]"}, 1)


def test_make_redactor_returns_a_fresh_instance_each_time(tmp_path):
    # One redactor per connection: sharing one would leak placeholders/known values across sessions.
    red = load_config(write(tmp_path, UP + "redaction:\n  fields: {ssn: SSN}\n")).redaction
    a, b = red.make_redactor(), red.make_redactor()
    assert a is not b
    a.redact({"ssn": "111-22-3333"})
    assert b.redact({"ssn": "444-55-6666"})[0] == {"ssn": "[SSN_1]"}


@pytest.mark.parametrize(
    "redaction, match",
    [
        ("redaction: nope\n", "must be a mapping"),
        ("redaction:\n  enabled: maybe\n", "true or false"),
        ("redaction:\n  enabled: true\n", "redact\\s+nothing|nothing"),
        ("redaction:\n  fields: [ssn]\n", "mapping of strings"),
        ("redaction:\n  fields: {ssn: 5}\n", "mapping of strings"),
        ("redaction:\n  fields: {ssn: lower}\n", "label"),
        ("redaction:\n  patterns: {SSN: '(unclosed'}\n", "invalid pattern"),
    ],
)
def test_invalid_redaction_config(tmp_path, redaction, match):
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, UP + redaction))


def test_example_config_is_valid_and_actually_redacts_the_fake_data(example_redaction):
    from fake_passport.server import TRAVELERS

    for record in TRAVELERS:
        out, count = example_redaction.make_redactor().redact(record)
        dumped = str(out)
        for raw in (record["name"], record["ssn"], record["passport_number"], record["email"],
                    record["phone"], record["dob"], record["address"], *record["mrz"]):
            assert raw not in dumped, f"{record['traveler_id']} leaked {raw!r}"
        assert count > 0
