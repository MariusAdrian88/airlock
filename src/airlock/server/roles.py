"""Session role and per-role tool gating (DESIGN 9).

Every session starts unbound. ``project_open`` (or a successful ``project_create``)
binds the process to one (project, role) for the rest of its life. The tool list is
the same in every role; gating happens when a tool is called.
"""

from __future__ import annotations

from dataclasses import dataclass

from airlock.config.catalog import CATALOG
from airlock.projects import ProjectPaths

DIRTY, CLEAN, UNBOUND = "dirty", "clean", "unbound"
UNBOUND_TOOLS = frozenset({"projects", "project_open", "project_create", "program_scan",
                           "project_info"})
BIND_TOOLS = frozenset({"project_open", "project_create"})


@dataclass(frozen=True)
class SessionState:
    role: str = UNBOUND
    project: ProjectPaths | None = None


def role_locked(session: SessionState) -> str:
    name = session.project.name if session.project else "-"
    return (f"error role_locked: this session is already {session.role} for {name}. "
            "Start a new session for other work.")


def gate(session: SessionState, tool: str) -> str | None:
    """None if the call may proceed, else the one-line error."""
    if session.role == UNBOUND:
        if tool in UNBOUND_TOOLS:
            return None
        return ("error unbound: no project is open. Call projects, then project_open "
                "(name, role), or project_create for a new program.")
    if tool in BIND_TOOLS:
        return role_locked(session)
    if session.role == CLEAN:
        info = CATALOG.get(tool)
        if info is not None and info.clean_safe:
            return None
        return (f"error wrong_role: {tool} is not available in a clean-room session. "
                "Use spec_read, spec_list or spec_export.")
    return None
