"""Session tracking. Not implemented yet (see the README roadmap).

Today a session is one proxy process, identified by the id AuditLog.start_session mints
at connection time. This module is reserved for richer session state, such as client info.
"""

from __future__ import annotations
