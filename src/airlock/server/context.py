"""Shared state handed to every tool implementation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import anyio

from airlock.config import Config
from airlock.server import roles
from airlock.server.indexer import Indexer
from airlock.worker.client import WorkerClient

log = logging.getLogger("airlock")


@dataclass
class ServerContext:
    config: Config
    worker: WorkerClient
    not_implemented: list[str] = field(default_factory=list)
    indexer: Indexer = field(init=False)
    session: roles.SessionState = field(default_factory=roles.SessionState)
    profile_role: str | None = None  # role of an explicit --profile, else None
    roots_done: bool = False

    def __post_init__(self) -> None:
        self.indexer = Indexer(self.config, self.worker)
        self._roots_lock = anyio.Lock()

    def set_session(self, state: roles.SessionState) -> None:
        self.session = state
        if state.role == roles.DIRTY and state.project is not None:
            self.indexer.current = state.project.name

    async def ensure_roots(self, mcp_session: Any) -> None:
        """Once per process: if the client offers roots, they decide the workspace
        (replacing the env/cwd guess made at start). Never changes the role afterwards."""
        async with self._roots_lock:
            if self.roots_done:
                return
            self.roots_done = True
            roots = await roles.roots_of(mcp_session)
            if not roots:
                return
            ws, source = roles.detect_workspace(roots)
            try:
                self.set_session(roles.resolve_session(ws, source, self.profile_role))
            except roles.RoleConflict as e:
                log.error("%s", e)
                self.session = roles.SessionState(roles.UNBOUND, None, ws, source, note=str(e))
