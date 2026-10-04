import json

import pytest

from mcp_proxy.audit import AuditLog, sha256_hex
from mcp_proxy.audit_cli import main as audit_cli


@pytest.fixture
def audit():
    a = AuditLog(":memory:")
    yield a
    a.close()


def test_session_and_call_roundtrip(audit):
    sid = audit.start_session("fake-ehr", client_name="claude-code")
    audit.record_call(
        sid,
        "get_patient",
        {"patient_id": "P1000"},
        result_redacted='{"name": "[PERSON_1]"}',
        result_sha256=sha256_hex("raw result"),
        redactions_count=3,
        latency_ms=12.5,
    )
    (row,) = audit.query_calls()
    assert row["session_id"] == sid
    assert row["tool"] == "get_patient"
    assert json.loads(row["args_json"]) == {"patient_id": "P1000"}
    assert row["result_redacted"] == '{"name": "[PERSON_1]"}'
    assert row["result_sha256"] == sha256_hex("raw result")
    assert row["redactions_count"] == 3
    assert row["cache_hit"] == 0 and row["is_error"] == 0

    (sess,) = audit.list_sessions()
    assert sess["client_name"] == "claude-code"
    assert sess["n_calls"] == 1


def test_args_json_is_canonical(audit):
    sid = audit.start_session("x")
    audit.record_call(sid, "t", {"b": 1, "a": 2})
    assert audit.query_calls()[0]["args_json"] == '{"a": 2, "b": 1}'


def test_error_and_cache_hit_flags(audit):
    sid = audit.start_session("x")
    audit.record_call(sid, "t", None, is_error=True, error="boom")
    audit.record_call(sid, "t", {"q": 1}, cache_hit=True)
    rows = {r["error"] is not None: r for r in audit.query_calls()}
    assert rows[True]["is_error"] == 1 and rows[True]["args_json"] is None
    assert rows[False]["cache_hit"] == 1


def test_filters_and_ordering(audit):
    s1, s2 = audit.start_session("x"), audit.start_session("x")
    audit.record_call(s1, "a", None)
    audit.record_call(s1, "b", None)
    audit.record_call(s2, "a", None)

    assert [r["tool"] for r in audit.query_calls(session_id=s1)] == ["b", "a"]  # newest first
    assert {r["session_id"] for r in audit.query_calls(tool="a")} == {s1, s2}
    assert len(audit.query_calls(session_id=s2, tool="b")) == 0
    assert len(audit.query_calls(limit=2)) == 2


def test_sessions_report_call_counts(audit):
    s1, s2 = audit.start_session("x"), audit.start_session("x")
    audit.record_call(s1, "a", None)
    audit.record_call(s1, "a", None)
    counts = {s["id"]: s["n_calls"] for s in audit.list_sessions()}
    assert counts == {s1: 2, s2: 0}


def test_persists_across_connections(tmp_path):
    path = tmp_path / "a.sqlite"
    a = AuditLog(path)
    sid = a.start_session("x")
    a.record_call(sid, "t", {"k": "v"})
    a.close()
    b = AuditLog(path)
    assert len(b.query_calls()) == 1
    b.close()


def test_cli_lists_sessions_and_calls(tmp_path, capsys):
    path = tmp_path / "a.sqlite"
    a = AuditLog(path)
    sid = a.start_session("fake-ehr")
    a.record_call(sid, "get_patient", {"patient_id": "P1"}, result_redacted="[X]",
                  result_sha256="abc", latency_ms=5)
    a.close()

    audit_cli(["--db", str(path), "sessions"])
    out = capsys.readouterr().out
    assert sid in out and "calls=1" in out

    audit_cli(["--db", str(path), "calls"])
    out = capsys.readouterr().out
    assert "get_patient" in out and "[X]" not in out  # result only with --full

    audit_cli(["--db", str(path), "calls", "--full"])
    out = capsys.readouterr().out
    assert "[X]" in out and "sha256: abc" in out


def test_cli_missing_db_exits_without_creating_it(tmp_path, capsys):
    path = tmp_path / "nope.sqlite"
    with pytest.raises(SystemExit) as exc:
        audit_cli(["--db", str(path), "calls"])
    assert exc.value.code == 2
    assert not path.exists()
    assert "no audit database" in capsys.readouterr().err
