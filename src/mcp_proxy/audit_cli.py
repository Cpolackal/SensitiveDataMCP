"""`mcp-audit` CLI: query the audit log.

    mcp-audit sessions
    mcp-audit calls [--session X] [--tool Y] [--limit N] [--full]
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from mcp_proxy.audit import AuditLog


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-audit", description="Query the MCP proxy audit log.")
    p.add_argument("--db", default="audit.sqlite", help="path to the audit database")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sessions", help="list sessions, newest first")
    s.add_argument("--limit", type=int, default=20)

    c = sub.add_parser("calls", help="list tool calls, newest first")
    c.add_argument("--session", help="only this session id")
    c.add_argument("--tool", help="only this tool name")
    c.add_argument("--limit", type=int, default=50)
    c.add_argument("--full", action="store_true", help="also print arguments and result")
    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    # Don't let a typo'd path silently create an empty database.
    if not Path(args.db).exists():
        print(f"mcp-audit: no audit database at {args.db}", file=sys.stderr)
        sys.exit(2)

    audit = AuditLog(args.db)
    try:
        if args.cmd == "sessions":
            for s in audit.list_sessions(args.limit):
                client = s["client_name"] or "-"
                print(
                    f"{s['id']}  {_fmt_ts(s['started_at'])}  upstream={s['upstream']}"
                    f"  client={client}  calls={s['n_calls']}"
                )
        else:
            for r in audit.query_calls(session_id=args.session, tool=args.tool, limit=args.limit):
                status = "ERR" if r["is_error"] else "ok "
                cache = " cached" if r["cache_hit"] else ""
                latency = f"{r['latency_ms']:.0f}ms" if r["latency_ms"] is not None else "-"
                print(
                    f"{_fmt_ts(r['ts'])}  {r['session_id']}  {status}  {r['tool']}"
                    f"  {latency}{cache}  redactions={r['redactions_count']}"
                )
                if args.full:
                    print(f"    args:   {r['args_json']}")
                    print(f"    result: {r['result_redacted']}")
                    print(f"    sha256: {r['result_sha256']}")
                    if r["error"]:
                        print(f"    error:  {r['error']}")
    finally:
        audit.close()


if __name__ == "__main__":
    main()
