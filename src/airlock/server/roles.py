"""Session role from the workspace folder, and per-role tool gating (DESIGN 9).

The role is dirty, clean or unbound. It comes from the folder the MCP client was
started in: MCP roots (first root), else CLAUDE_PROJECT_DIR (set by Claude Code;
read as client-provided detection, not airlock configuration), else the process
working directory. It is resolved once and never changes. The tool list is the same
in every role; gating happens when a tool is called.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from airlock.config.catalog import CATALOG
from airlock.projects import ProjectPaths, locate_project

DIRTY, CLEAN, UNBOUND = "dirty", "clean", "unbound"
UNBOUND_TOOLS = frozenset({"program_scan", "project_create", "project_info"})
UNBOUND_ONLY_TOOLS = frozenset({"project_create"})


class RoleConflict(Exception):
    """--profile contradicts the folder role."""


@dataclass(frozen=True)
class SessionState:
    role: str = UNBOUND
    project: ProjectPaths | None = None
    workspace: Path | None = None
    source: str = "cwd"  # roots | env CLAUDE_PROJECT_DIR | cwd | profile
    note: str = ""


def uri_to_path(uri: str) -> Path | None:
    u = urlparse(str(uri))
    if u.scheme != "file":
        return None
    path = url2pathname(unquote(u.path))
    if u.netloc and u.netloc != "localhost":
        path = "\\\\" + u.netloc + path
    return Path(path) if path else None


def detect_workspace(roots: list[str] | None = None) -> tuple[Path | None, str]:
    for r in roots or []:
        p = uri_to_path(r)
        if p is not None:
            return p, "roots"
        break  # only the first root counts
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env), "env CLAUDE_PROJECT_DIR"
    try:
        return Path(os.getcwd()), "cwd"
    except OSError:
        return None, "cwd"


def resolve_session(workspace: Path | None, source: str,
                    profile_role: str | None = None) -> SessionState:
    """Role and project for a workspace. ``profile_role`` is the role of an explicit
    --profile: it may not contradict the folder; in an unbound folder it applies as is."""
    found = locate_project(workspace) if workspace is not None else None
    if found is None:
        if profile_role:
            return SessionState(profile_role, None, workspace, "profile")
        return SessionState(UNBOUND, None, workspace, source)
    role, pp = found
    if profile_role and profile_role != role:
        raise RoleConflict(
            f"--profile has role {profile_role} but the workspace is the {role} folder of "
            f"project {pp.name}. Start the client in the matching folder or drop --profile.")
    return SessionState(role, pp, workspace, source)


def gate(session: SessionState, tool: str) -> str | None:
    """None if the call may proceed, else the one-line error."""
    if session.note:
        return f"error wrong_role: {session.note}"
    if session.role == UNBOUND:
        if tool in UNBOUND_TOOLS:
            return None
        return ("error unbound: this session is not in a project folder. Ask to reverse "
                "engineer a program (project_create) or start the client in "
                "<project>\dirty or \clean.")
    if session.role == CLEAN:
        info = CATALOG.get(tool)
        if info is not None and info.clean_safe:
            return None
        return (f"error wrong_role: {tool} is not available in a clean-room session. "
                "Use spec_read, spec_list or spec_export.")
    if tool in UNBOUND_ONLY_TOOLS and session.project is not None:
        return (f"error wrong_role: already in project {session.project.name}. "
                f"{tool} is only for sessions outside a project folder.")
    return None


async def roots_of(mcp_session: Any) -> list[str] | None:
    """The client's root URIs, or None when it does not offer roots (or the call fails)."""
    import warnings

    import anyio

    caps = getattr(mcp_session, "client_capabilities", None)
    if caps is None or getattr(caps, "roots", None) is None:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with anyio.fail_after(5):
                res = await mcp_session.list_roots()
    except Exception:
        return None
    return [str(r.uri) for r in res.roots]
