"""Shared state handed to every tool implementation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
import threading

from airlock import logs
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
    focus: dict[str, int] = field(default_factory=dict)  # project -> binary id viewed last (7.3 rule 9)

    def __post_init__(self) -> None:
        self.indexer = Indexer(self.config, self.worker)
        self._bind_lock = threading.Lock()
        self._maps_lock = threading.Lock()
        self._refresh_lock = threading.Lock()   # one derivation + map rewrite at a time
        self._maps_pending: set[str] = set()
        self._maps_thread: threading.Thread | None = None
        self.indexer.ready_hooks.append(self._on_ready)

    def _on_ready(self, project: str, binary_id: int) -> None:
        """A binary became ready: queue a (coalesced) feature derivation + PROJECT.md rewrite on a
        background thread, so the analysis queue never waits for it."""
        with self._maps_lock:
            self._maps_pending.add(project)
            if self._maps_thread is not None:
                return
            self._maps_thread = threading.Thread(target=self._maps_loop, name="airlock-maps",
                                                 daemon=True)
            self._maps_thread.start()

    def _maps_loop(self) -> None:
        while True:
            with self._maps_lock:
                if not self._maps_pending:
                    self._maps_thread = None
                    return
                project = self._maps_pending.pop()
            try:
                self.refresh_maps(project)
            except Exception as e:  # noqa: BLE001  the map is an extra
                logs.project_log(self.indexer.paths(project).logs).warning(
                    "feature derivation / map refresh failed for %s: %s", project, e)

    def refresh_maps(self, project: str) -> None:
        """Derive the feature index and rewrite both PROJECT.md files now (this thread)."""
        with self._refresh_lock:
            self._refresh_maps(project)

    def _refresh_maps(self, project: str) -> None:
        from airlock.server import features, projectmap

        st = self.indexer.store(project)
        pp = self.indexer.paths(project)
        man = projectmap.load_manifest(pp)  # parsed once: JSONC parsing is the slow part
        from airlock.server import peres

        peres.ensure_project(st, pp.artifacts)   # old projects: resource tables missing or stale
        from airlock.server import cpp

        cpp.ensure_project(st, pp.artifacts)     # old projects: C++ tables missing or stale
        features.derive_project(pp, st, man)
        projectmap.write_maps(pp, st, man, mermaid=bool(self.config.defaults.get("mermaid")))

    def wait_maps(self, timeout: float = 30.0) -> bool:
        """Wait until no derivation is pending or running (tests, shutdown)."""
        t = self._maps_thread
        if t is not None:
            t.join(timeout)
        with self._maps_lock:
            return not self._maps_pending and self._maps_thread is None

    def bind_session(self, role: str, pp: ProjectPaths) -> str | None:
        """Bind the process to (project, role) once. None on success, else the error line."""
        if role not in (roles.DIRTY, roles.CLEAN):
            return f"error bad_role: role '{role}' is not dirty or clean."
        with self._bind_lock:
            if self.session.role != roles.UNBOUND:
                return roles.role_locked(self.session)
            if self.profile_role and self.profile_role != role:
                return (f"error wrong_role: this server was started with --profile "
                        f"{self.profile_role}.")
            self.session = roles.SessionState(role, pp)
            if role == roles.DIRTY:
                self.indexer.current = pp.name
        if role == roles.DIRTY:
            try:
                self.indexer.resume_project(pp.name)
            except Exception as e:  # noqa: BLE001  resuming is an extra; the session stays bound
                logs.project_log(pp.logs).warning("resume_project(%s) failed: %s", pp.name, e)
        return None
