"""Session tracking (phase 3).

stdio MCP has no conversation id; one proxy process == one session. Generate an id
at startup and record client info from initialize. Also home of the per-session
placeholder map used for stable redaction ([PERSON_1], ...).
"""

from __future__ import annotations
