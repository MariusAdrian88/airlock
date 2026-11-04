"""Shared state handed to every tool implementation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
import threading

from airlock.config import Config
from airlock.projects import ProjectPaths
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

    def __post_init__(self) -> None:
        self.indexer = Indexer(self.config, self.worker)
        self._bind_lock = threading.Lock()

    def bind_session(self, role: str, pp: ProjectPaths) -> str | None:
        """Bind the process to (project, role) once. None on success, else the error line."""
        if role not in (roles.DIRTY, roles.CLEAN):
            return f"error bad_role: role '{role}' is not dirty or clean. Use dirty or clean."
        with self._bind_lock:
            if self.session.role != roles.UNBOUND:
                return roles.role_locked(self.session)
            if self.profile_role and self.profile_role != role:
                return (f"error wrong_role: this server was started with --profile "
                        f"{self.profile_role}.")
            self.session = roles.SessionState(role, pp)
            if role == roles.DIRTY:
                self.indexer.current = pp.name
        return None
