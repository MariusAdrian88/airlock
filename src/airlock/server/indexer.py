"""Indexing orchestration (DESIGN.md section 5), server side. Never imports pyghidra.

Every binary goes through ONE queue and one queue thread (one binary at a time, priority
core -> own_plugin -> others by code size). open_binary and ``enqueue`` (manifest entries,
program_add, resume after a restart) register the binary (status ``queued``); the thread runs
ensure_ghidra, open_project, import_binary (+ external library links to programs already in
the project), analyze. When the worker reports analysis ``done``, a second thread pages
through the ``extract`` kinds into the project's Store, links edges, rebuilds the FTS table,
sets the binary ``ready`` and links it to the project's other binaries (import slot -> export).

Binary status lives in the index ``meta`` table (``status:<id>``) and, mirrored, in the
manifest file entry (``state``), with measured ``analysis_s``/``code_size`` that refine the
remaining-time estimate: queued -> importing -> analysing -> extracting -> finishing -> ready | error.
``finishing`` is the after-ready work (toolchain tables, missing functions, Qt dispatch, links,
ready hooks); ``ready`` means all index work is done (the background decompile pass runs after it
and has its own progress). Tools already work during ``finishing``.
A persisted non-final status with no live job means the server stopped mid-way;
``resume_project`` (first use of the project) queues it again; an interrupted ``finishing`` is
completed by the refresh steps there (no re-analysis).
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from airlock import logs
from airlock.config import Config
from airlock.index.store import USABLE_STATES, Binary, Store
from airlock.server import estimate as est
from airlock.server import cpp, delphi, dotnet, fnfix, linking, peres, qt
from airlock.server.bulk import SKIP_GROUPS, BulkScheduler
from airlock.projects import (
    ProjectPaths, copy_artifact, detect, hash_file, list_projects, project_paths, read_manifest,
    read_sections, slugify, write_manifest,
)
from airlock.worker.protocol import WorkerError

GHIDRA_PROJECT_NAME = "airlock"
EXTRACT_KINDS = ("functions", "imports", "exports", "strings", "edges")
PAGE_SIZE = {"functions": 5000, "imports": 5000, "exports": 5000, "strings": 5000, "edges": 10000}
GROUP_RANK = {"core": 0, "own_plugin": 1}  # every other group ranks 2
ACTIVE = ("importing", "analysing", "extracting", "finishing")
DECOMPILE_FN_PER_S = 200.0  # prior of the background pass, until a rate has been measured
_MB = 1 << 20
log = logging.getLogger("airlock")
FINAL = ("ready", "error")
USABLE = USABLE_STATES   # tools may read the binary: its data is extracted
MANAGED_S = 1.0      # estimate for indexing one IL-only assembly
OPEN_WAIT_S = 30.0


class IndexerError(Exception):
    """Carries a ready-to-return one-line error in project format (.message)."""

    def __init__(self, code: str, what: str, action: str = "") -> None:
        self.code = code
        self.message = f"error {code}: {what}." + (f" {action}." if action else "")
        super().__init__(self.message)


WORKER_LOG_FACT = "details in logs\\worker.log"


def worker_error(e: WorkerError, action: str = WORKER_LOG_FACT) -> str:
    msg = e.message.rstrip(". ")
    return f"error {e.code}: {msg}." + (f" {action}." if action else "")


def program_name_for(file_name: str) -> str:
    """Program name inside the Ghidra project: the slug of the file name."""
    return slugify(file_name)


# ── row mapping (worker extract rows -> Store inserts) ────────────────────────

def _dicts(columns: list[str], rows: list[list[Any]]) -> list[dict[str, Any]]:
    return [dict(zip(columns, r)) for r in rows]


def map_function_rows(columns: list[str], rows: list[list[Any]]) -> list[dict[str, Any]]:
    out = []
    for d in _dicts(columns, rows):
        out.append({
            "space": d["space"], "entry": d["entry"], "name": d["name"],
            "name_state": d["name_state"], "namespace": d.get("namespace") or None,
            "signature": d.get("signature"), "calling_conv": d.get("calling_conv"),
            "size": d.get("size"), "is_thunk": bool(d.get("is_thunk")),
            "is_external": bool(d.get("is_external")),
        })
    return out


def map_import_rows(columns: list[str], rows: list[list[Any]]) -> list[tuple]:
    return [(d["dll"], d["name"], d["ordinal"], d["address"]) for d in _dicts(columns, rows)]


def map_export_rows(columns: list[str], rows: list[list[Any]]) -> list[tuple]:
    """(name, ordinal, address) of exports in ram space."""
    return [(d["name"], d["ordinal"], d["address"])
            for d in _dicts(columns, rows) if d["space"] == "ram"]


def map_string_rows(columns: list[str], rows: list[list[Any]]) -> list[tuple]:
    """(address, encoding, value); strings outside ram have no column to live in."""
    return [(d["address"], d["encoding"], d["value"])
            for d in _dicts(columns, rows) if d["space"] == "ram"]


def map_edge_rows(columns: list[str], rows: list[list[Any]]) -> list[tuple]:
    """(src_addr, dst_addr, kind); edges into EXTERNAL space are dropped (the edge
    table has no destination space, and the import thunk/IAT edges carry the call)."""
    return [(d["src_addr"], d["dst_addr"], d["kind"])
            for d in _dicts(columns, rows) if d["dst_space"] == "ram"]


def run_extraction(worker: Any, store: Store, binary_id: int, program: str,
                   on_kind: Callable[[str, int], None] | None = None,
                   artifact: Path | None = None, project: str | None = None) -> dict[str, Any]:
    """Page through all four kinds into ``store``; returns counts, timings, image
    base and pointer size. Idempotent: derived rows are cleared first. ``project`` (the Ghidra
    project folder) makes the worker refuse the reads when another project is open."""
    store.clear_binary_data(binary_id)
    counts: dict[str, int] = {}
    secs: dict[str, float] = {}
    image_base = pointer_size = None
    for kind in EXTRACT_KINDS:
        t0 = time.monotonic()
        offset, n = 0, 0
        while True:
            args = {"program": program, "kind": kind, "offset": offset, "limit": PAGE_SIZE[kind]}
            if project:
                args["project"] = project
            r = worker.request("extract", args, timeout=900)
            image_base, pointer_size = r.get("image_base"), r.get("pointer_size")
            cols, rows = r["columns"], r["rows"]
            if kind == "functions":
                store.insert_functions(binary_id, map_function_rows(cols, rows))
            elif kind == "imports":
                store.insert_imports(binary_id, map_import_rows(cols, rows))
            elif kind == "exports":
                store.insert_exports(binary_id, map_export_rows(cols, rows))
            elif kind == "strings":
                store.insert_strings(binary_id, map_string_rows(cols, rows))
            else:
                store.insert_edges(binary_id, map_edge_rows(cols, rows))
            n += len(rows)
            if r.get("done") or r.get("next_offset") is None:
                break
            offset = r["next_offset"]
        counts[kind] = n
        secs[kind] = round(time.monotonic() - t0, 2)
        if on_kind:
            on_kind(kind, n)
    t0 = time.monotonic()
    try:
        linking.record_sections(store, binary_id, artifact)   # fnptr tables only in data sections
    except Exception:  # noqa: BLE001
        log.warning("sections of binary %s unreadable", binary_id)
    store.link_edges(binary_id)
    store.rebuild_fts(binary_id)
    secs["link_fts"] = round(time.monotonic() - t0, 2)
    return {"counts": counts, "secs": secs, "image_base": image_base,
            "pointer_size": pointer_size}


# ── jobs ──────────────────────────────────────────────────────────────────────

@dataclass
class Job:
    project: str
    binary_id: int
    program: str
    artifact: Path
    paths: ProjectPaths
    started: float = field(default_factory=time.monotonic)
    reached: threading.Event = field(default_factory=threading.Event)  # analysing/ready/error
    lock: threading.Lock = field(default_factory=threading.Lock)
    extracting: bool = False
    finished: threading.Event = field(default_factory=threading.Event)
    timings: dict[str, float] = field(default_factory=dict)
    sha256: str = ""
    rel_path: str | None = None
    group: str = "core"
    code_size: int = 0
    est_funcs: int = 0
    seq: int = 0
    analysis_started: float | None = None
    already_analysed: bool = False
    managed: bool = False         # IL-only assembly: metadata index only, no Ghidra
    step: str = ""                # what the after-ready work is doing (status finishing)

    @property
    def priority(self) -> tuple[int, int, int]:
        """core, then own_plugin, then the rest; within a group the smaller code size first."""
        return GROUP_RANK.get(self.group, 2), self.code_size, self.seq


@dataclass(frozen=True)
class QueueRow:
    binary_id: int
    name: str
    state: str
    seconds: float | None      # elapsed so far (running) or measured analysis time (ready)
    est_seconds: float | None  # estimate (not finished)
    code_size: int


@dataclass(frozen=True)
class QueueStatus:
    rows: tuple[QueueRow, ...]       # current first, then waiting in run order, then the rest
    remaining_s: float
    s_per_mb: float
    current: QueueRow | None
    overhead_s: float = 0.0          # fixed seconds per binary
    over_s: float = 0.0              # seconds the current binary is past its estimate
    decompile_fns: int = 0           # functions the background pass still has to decompile
    decompile_s: float = 0.0         # ... and its estimate


@dataclass(frozen=True)
class OpenResult:
    binary: Binary
    status: str
    note: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Indexer:
    def __init__(self, config: Config, worker: Any) -> None:
        self.config = config
        self.worker = worker
        self.current: str | None = None  # project of the last open_binary
        self._tls = threading.local()
        self._jobs: dict[tuple[str, int], Job] = {}
        self._by_program: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._queue: list[Job] = []          # waiting jobs (guarded by _lock)
        self._running: Job | None = None     # the job the queue thread is on
        self._runner: threading.Thread | None = None
        self._seq = itertools.count()
        self._mf_lock = threading.RLock()
        self._switch = threading.Lock()      # the worker's open project changes under this lock only
        self._resumed: set[str] = set()
        # callbacks(project, binary_id) run after a binary became ready and was linked
        self.ready_hooks: list[Callable[[str, int], None]] = []
        worker.on_event(self._on_event)
        self.bulk = BulkScheduler(self)  # background decompile pass (server/bulk.py)

    def queue_idle(self) -> bool:
        """True when no binary is being analysed or waiting for analysis."""
        with self._lock:
            return self._running is None and not self._queue

    # -- stores / projects -------------------------------------------------

    def paths(self, project: str, create: bool = False) -> ProjectPaths:
        return project_paths(self.config.projects_root, project, create=create)

    def store(self, project: str) -> Store:
        """This thread's Store for the project (sqlite connections are per thread)."""
        slug = slugify(project)
        stores = self._tls.__dict__.setdefault("stores", {})
        st = stores.get(slug)
        if st is None:
            st = stores[slug] = Store(self.paths(slug, create=True).index_db)
        return st

    def projects(self) -> list[str]:
        return list_projects(self.config.projects_root)

    def resolve_project(self, project: str | None = None) -> str:
        """Explicit project, else the last opened one, else the only one on disk."""
        slug = self._resolve_project(project)
        self.resume_project(slug)
        return slug

    def _resolve_project(self, project: str | None) -> str:
        if project:
            slug = slugify(project)
            if slug not in self.projects():
                have = ", ".join(self.projects()) or "none"
                raise IndexerError("no_project", f"project '{project}' does not exist (have: {have})")
            return slug
        if self.current:
            return self.current
        known = self.projects()
        if len(known) == 1:
            return known[0]
        if not known:
            raise IndexerError("no_project", "no project exists yet")
        raise IndexerError("ambiguous_project", f"{len(known)} projects exist: {', '.join(known)}")

    # -- status ------------------------------------------------------------

    def get_status(self, store: Store, binary_id: int) -> tuple[str, str | None]:
        return store.get_meta(f"status:{binary_id}") or "queued", store.get_meta(f"error:{binary_id}")

    def set_status(self, store: Store, binary_id: int, status: str, error: str | None = None) -> None:
        with store.db:
            store.set_meta(f"status:{binary_id}", status)
            store.set_meta(f"error:{binary_id}", error or "")

    def program_of(self, store: Store, b: Binary) -> str:
        return store.get_meta(f"program:{b.id}") or program_name_for(b.name)

    def job_for(self, project: str, binary_id: int) -> Job | None:
        return self._jobs.get((project, binary_id))

    def describe(self, project: str, store: Store, b: Binary) -> tuple[str, str]:
        """(status, detail) for display; detail has progress or the error text."""
        status, err = self.get_status(store, b.id)
        job = self.job_for(project, b.id)
        if status == "error":
            return status, err or "unknown error"
        if status == "ready":
            return status, ""
        if status == "finishing" and job is not None:
            return status, job.step or "tables"
        if job is None:
            return "interrupted", f"was {status} when the server stopped"
        if status == "queued":
            with self._lock:
                waiting = sorted(self._queue, key=lambda j: j.priority)
            pos = waiting.index(job) + 1 if job in waiting else 0
            return status, (f"waiting, position {pos} of {len(waiting)}" if pos else "waiting")
        if status == "analysing":
            p = self.worker.progress(job.program) or {}
            bits = []
            if p.get("pct") is not None:
                bits.append(f"{p['pct']}%")
            if p.get("analyzers_done") is not None:
                bits.append(f"{p['analyzers_done']} analyzers done")
            if p.get("functions") is not None:
                bits.append(f"{p['functions']} functions")
            bits.append(f"{round(time.monotonic() - job.started)}s")
            return status, ", ".join(bits)
        return status, f"{round(time.monotonic() - job.started)}s"

    def not_ready_error(self, project: str, store: Store, b: Binary) -> str | None:
        """One-line not_analysed error, or None when the binary is ready."""
        status, detail = self.describe(project, store, b)
        if status in USABLE:
            return None
        if status == "interrupted" and self._requeue(project, store, b):
            status, detail = self.describe(project, store, b)
            detail += "; resumed after a server stop"
        if status == "error":
            return f"error not_analysed: binary '{b.name}' failed to index ({detail})."
        return f"error not_analysed: binary '{b.name}' is {status} ({detail})."

    def _requeue(self, project: str, store: Store, b: Binary) -> bool:
        """Queue an interrupted binary again from its stored artifact. True when queued."""
        try:
            if not (self.paths(project).artifacts / b.sha256).is_file():
                return False
            return bool(self.enqueue(project, [{"sha256": b.sha256, "path": b.name, "group": "core"}]))
        except Exception:  # noqa: BLE001  resuming is an extra; the error line stays
            return False

    # -- open_binary / queue -------------------------------------------------

    def open_binary(self, project: str, path: str, wait_s: float = OPEN_WAIT_S) -> OpenResult:
        src = Path(path).expanduser()
        if not src.is_file():
            raise IndexerError("not_found", f"file '{path}' does not exist")
        info = detect(src)
        if info.format == "not-pe":
            raise IndexerError("unsupported", f"'{src.name}' is not a PE file",
                               "airlock opens Windows PE executables and DLLs")
        paths = self.paths(project, create=True)
        self.current = paths.name
        store = self.store(paths.name)
        sha = hash_file(src)
        existing = next((b for b in store.list_binaries() if b.sha256 == sha), None)
        if existing is not None:
            status, _ = self.get_status(store, existing.id)
            live = self.job_for(paths.name, existing.id)
            if status == "ready" or live is not None:
                return OpenResult(existing, status, "already opened")
        sha, _ = copy_artifact(src, paths, sha)
        job = self._enqueue_one(paths, store, sha, src.name, None, "core", None, str(src))
        assert job is not None
        job.reached.wait(wait_s)
        b = store.get_binary_by_id(job.binary_id)
        assert b is not None
        status, _ = self.get_status(store, job.binary_id)
        note = "resumed after restart" if existing is not None else None
        return OpenResult(b, status, note)

    def enqueue(self, project: str, files: list[dict[str, Any]]) -> list[str]:
        """Queue manifest file entries ({path, sha256, group, code_size, ...}; the artifact is
        ``artifacts/<sha256>``). Binaries already ready or queued are skipped. Returns the
        rel_paths queued."""
        paths = self.paths(project, create=True)
        store = self.store(paths.name)
        queued = []
        for f in files:
            sha = f.get("sha256")
            rel = f.get("path") or f.get("rel_path")
            if not sha or not rel or f.get("kind", "pe") != "pe":
                continue
            if not (paths.artifacts / sha).is_file():
                self._mf_update(paths.name, sha, state="error", error="artifact missing")
                continue
            job = self._enqueue_one(paths, store, sha, Path(str(rel).replace("\\", "/")).name,
                                    rel, f.get("group") or "other", f.get("code_size"),
                                    str(f.get("source") or rel), int(f.get("est_funcs") or 0))
            if job is not None:
                queued.append(rel)
        return queued

    def resume_project(self, project: str) -> int:
        """Once per process and project: queue the manifest entries and index binaries that are
        neither ready nor failed (the server stopped before they finished). Returns the count."""
        slug = slugify(project)
        with self._lock:
            if slug in self._resumed:
                return 0
            self._resumed.add(slug)
        if slug not in self.projects():
            return 0
        paths = self.paths(slug)
        plog = logs.project_log(paths.logs)
        n = 0
        store = self.store(slug)
        for b in store.list_binaries():   # the server stopped in the after-ready work: the refresh steps below redo it
            if self.get_status(store, b.id)[0] == "finishing" and self.job_for(slug, b.id) is None:
                self.set_status(store, b.id, "ready")
                self._mf_update(slug, b.sha256, state="ready")
        try:
            man = read_manifest(paths.manifest)
        except (OSError, ValueError):
            man = {}
        todo = [f for f in man.get("files") or []
                if f.get("kind", "pe") == "pe" and f.get("state", "queued") not in ("ready", "error")]
        n += len(self.enqueue(slug, todo))
        for b in store.list_binaries():  # opened with open_binary, no manifest entry
            status, _ = self.get_status(store, b.id)
            if status in FINAL or self.job_for(slug, b.id) is not None:
                continue
            if (paths.artifacts / b.sha256).is_file():
                n += len(self.enqueue(slug, [{"sha256": b.sha256, "path": b.name, "group": "core"}]))
        if self._other_busy(slug):   # the refresh steps below open this project in the worker: later
            with self._lock:
                self._resumed.discard(slug)
            return n
        try:
            self.refresh_fixups(slug, store)  # older post-analysis fixups: no re-analysis
        except Exception as e:  # noqa: BLE001  an extra; the binaries stay usable
            plog.warning("cannot refresh the fixups of %s: %s", slug, e)
        try:
            if linking.needs_relink(store):  # links built by an older version: no re-analysis
                ready = linking.ready_ids(store)
                linking.relink_project(store, paths.artifacts,
                                       after=(lambda: self._fire_ready(slug, ready[0])) if ready else None)
        except Exception as e:  # noqa: BLE001  links are an extra
            plog.warning("cannot relink %s: %s", slug, e)
        try:
            from airlock.server import features as _fx  # features derived by an older version: derive again
            ready = linking.ready_ids(store)
            if ready and store.feature_stats() and _fx.stale(store) and not linking.needs_relink(store):
                self._fire_ready(slug, ready[0])
        except Exception as e:  # noqa: BLE001  the feature index is an extra
            plog.warning("cannot refresh the features of %s: %s", slug, e)
        try:
            dotnet.ensure_project(store, paths.artifacts, linking.ready_ids(store))   # .NET tables stale
        except Exception as e:  # noqa: BLE001  an extra
            plog.warning("cannot refresh the .NET tables of %s: %s", slug, e)
        try:
            cpp.ensure_project(store, paths.artifacts)  # C++ tables missing or stale: no re-analysis
        except Exception as e:  # noqa: BLE001  an extra
            plog.warning("cannot refresh the C++ tables of %s: %s", slug, e)
        try:
            delphi.ensure_project(store, paths.artifacts, self.config.idr_kb_dir, self.config.delphi_sigdb_dir,
                                  self.config.warp_dir)  # Delphi tables and IDR names missing or stale: no re-analysis
        except Exception as e:  # noqa: BLE001  an extra
            plog.warning("cannot refresh the Delphi tables of %s: %s", slug, e)
        try:
            qt.ensure_project(store, paths.artifacts)  # Qt metaobject tables missing or stale: no re-analysis
        except Exception as e:  # noqa: BLE001  an extra
            plog.warning("cannot refresh the Qt tables of %s: %s", slug, e)
        try:
            if self.refresh_missing_functions(slug, store):   # C++ entry points without a function
                ready = linking.ready_ids(store)
                linking.relink_project(store, paths.artifacts,
                                       after=(lambda: self._fire_ready(slug, ready[0])) if ready else None)
        except Exception as e:  # noqa: BLE001  an extra
            plog.warning("cannot create the missing functions of %s: %s", slug, e)
        try:
            qt.resolve_project(self, slug, store)   # Qt method addresses and imported parents (worker)
        except Exception as e:  # noqa: BLE001  an extra
            plog.warning("cannot resolve the Qt methods of %s: %s", slug, e)
        try:
            self.bulk.resume(slug)  # ready binaries whose decompile pass was cut short
        except Exception as e:
            plog.warning("cannot resume the decompile pass of %s: %s", slug, e)
        return n

    def refresh_fixups(self, project: str, store: Store) -> int:
        """Ready binaries whose stored collector version (meta ``collector:<id>``) is not the
        worker's: run the worker's ``apply_fixups`` (no re-analysis), re-read the function rows
        (calling conventions) and store the new analysis profile, which invalidates the old
        decompiles. Returns the number of binaries refreshed."""
        n = 0
        for b in store.list_binaries():
            if self.get_status(store, b.id)[0] != "ready" or self.job_for(project, b.id) is not None:
                continue
            have = store.get_meta(f"collector:{b.id}")
            program = store.get_meta(f"program:{b.id}")
            if not program:
                continue
            self.ensure_open(project)
            res = self.worker.request("apply_fixups", {
                "program": program, "have_collector": int(have) if have else None,
                "parameter_id": bool(self.config.defaults.get("decompiler_parameter_id", True)),
            }, timeout=3600)
            if res.get("skipped"):
                continue
            offset = 0
            while True:  # functions only: the upsert bumps the version of changed rows
                r = self.worker.request("extract", {"program": program, "kind": "functions",
                                                    "offset": offset, "limit": PAGE_SIZE["functions"]},
                                        timeout=900)
                store.insert_functions(b.id, map_function_rows(r["columns"], r["rows"]))
                if r.get("done") or r.get("next_offset") is None:
                    break
                offset = r["next_offset"]
            if delphi.is_delphi(b) and (int(have) if have else 0) < 12:   # collector 12: ShortString literals
                self._add_new_strings(store, b.id, program)
            store.rebuild_fts(b.id)
            store.upsert_binary(b.sha256, b.name, analysis_profile=res.get("analysis_profile"))
            store.set_meta(f"collector:{b.id}", str(res.get("collector")))
            n += 1
        return n

    def _add_new_strings(self, store: Store, binary_id: int, program: str) -> int:
        """Read the strings again and add the rows at addresses that have none (no row is changed)."""
        have = {r[0] for r in store.db.execute("SELECT address FROM string WHERE binary_id=?", (binary_id,))}
        added, offset = 0, 0
        while True:
            r = self.worker.request("extract", {"program": program, "kind": "strings", "offset": offset,
                                                "limit": PAGE_SIZE["strings"]}, timeout=900)
            new = [row for row in map_string_rows(r["columns"], r["rows"]) if row[0] not in have]
            have.update(row[0] for row in new)
            if new:
                store.insert_strings(binary_id, new)
                added += len(new)
            if r.get("done") or r.get("next_offset") is None:
                return added
            offset = r["next_offset"]

    def create_missing_functions(self, project: str, store: Store, b: Binary,
                                 progress: Callable[[int, int], None] | None = None) -> int:
        """Create the functions Ghidra missed at message map handlers and vtable targets of ``b``
        (needs the C++ tables), then re-read the binary's functions and edges. Once per
        ``fnfix.FIX_VERSION`` and binary (meta). Returns the number of functions created."""
        program = store.get_meta(f"program:{b.id}")
        if not program or not fnfix.stale(store, b.id) or cpp.stale(store, b.id)                 or (delphi.is_delphi(b) and delphi.stale(store, b.id)):
            return 0
        if not fnfix.candidates(store, b.id):
            fnfix.record(store, b.id, {"requested": 0, "created": 0, "skipped": 0, "failed": 0,
                                       "reasons": {}})
            return 0
        self.ensure_open(project)
        t0 = time.monotonic()
        plog = logs.project_log(self.paths(project).logs)

        def recover() -> None:      # the worker process died: reopen the program, read what was saved
            self.ensure_open(project)
            self.reextract_code(store, b, program)

        try:
            res = fnfix.run(store, b.id, self.worker, program, recover=recover, log=plog.info,
                            progress=progress)
        except WorkerError as e:
            if e.code != "worker_stopped":
                raise
            plog.info("missing functions of %s: interrupted by the server shutdown; done again at the next open",
                      b.name)
            return 0
        # "exists" for an address the index has no function for: an earlier run created it, then the worker
        # died before the index was refreshed (seen once on a Delphi DLL) - read the functions back too
        if res["created"] or (res.get("reasons") or {}).get("exists"):
            self.reextract_code(store, b, program)
        fnfix.record(store, b.id, res)
        logs.project_log(self.paths(project).logs).info(
            "missing functions of %s: %s of %s created, %s failed (%.0fs)", b.name,
            res["created"], res["requested"], res["failed"], time.monotonic() - t0)
        return int(res["created"])

    def refresh_missing_functions(self, project: str, store: Store) -> int:
        """``create_missing_functions`` for the ready binaries not done at this version. Returns
        the number of functions created (the caller relinks when above zero)."""
        n = 0
        for b in store.list_binaries():
            if self.get_status(store, b.id)[0] != "ready" or self.job_for(project, b.id) is not None:
                continue
            try:
                n += self.create_missing_functions(project, store, b)
            except Exception as e:  # noqa: BLE001  one binary must not stop the others
                logs.project_log(self.paths(project).logs).warning("missing functions of %s: %s", b.name, e)
        return n

    def reextract_code(self, store: Store, b: Binary, program: str) -> None:
        """Re-read the functions (upsert: ids and decompiles of unchanged rows stay) and replace
        the edges of one binary, then rebuild the links derived from them. Strings, imports and
        exports do not depend on new functions."""
        for kind in ("functions", "edges"):
            offset = 0
            while True:
                r = self.worker.request("extract", {"program": program, "kind": kind, "offset": offset,
                                                    "limit": PAGE_SIZE[kind]}, timeout=900)
                if kind == "functions":
                    store.insert_functions(b.id, map_function_rows(r["columns"], r["rows"]))
                else:
                    if offset == 0:
                        with store.db:
                            store.db.execute("DELETE FROM edge WHERE binary_id=?", (b.id,))
                    store.insert_edges(b.id, map_edge_rows(r["columns"], r["rows"]))
                if r.get("done") or r.get("next_offset") is None:
                    break
                offset = r["next_offset"]
        store.link_edges(b.id)
        store.rebuild_fts(b.id)

    def _enqueue_one(self, paths: ProjectPaths, store: Store, sha: str, name: str,
                     rel_path: str | None, group: str, code_size: int | None,
                     original_path: str | None, est_funcs: int = 0) -> Job | None:
        """Register the binary (status queued) and put a job on the queue. None when the binary
        is ready, already queued/running, or not analysable."""
        slug = paths.name
        artifact = paths.artifacts / sha
        existing = next((b for b in store.list_binaries() if b.sha256 == sha), None)
        if existing is not None:
            status, _ = self.get_status(store, existing.id)
            if self.job_for(slug, existing.id) is not None:
                return None
            if status == "ready":
                self._mf_update(slug, sha, state="ready")
                return None
        info = detect(artifact)
        if info.format == "not-pe":
            self._mf_update(slug, sha, state="error", error="not a PE file")
            return None
        managed = info.toolchain == "dotnet" and info.managed_only
        if managed:
            code_size = 0     # IL only: indexed with dnfile on the server, Ghidra never sees it
        elif code_size is None:
            code_size = sum(vs for _n, _rva, vs, flags in read_sections(artifact) if "x" in flags)
        bid = store.upsert_binary(
            sha, name, original_path=original_path, format="dotnet" if managed else info.format,
            arch=info.arch, pointer_size=info.pointer_size, image_base=info.image_base,
            toolchain=info.toolchain, toolchain_ver=info.toolchain_ver, imported_at=_now(),
        )
        if managed:
            program = (store.get_meta(f"program:{bid}") if existing is not None else None) \
                or self._free_program_name(store, name, sha)
            store.set_meta(f"program:{bid}", program)
            job = Job(slug, bid, program, artifact, paths, sha256=sha, rel_path=rel_path, group=group,
                      code_size=0, seq=next(self._seq), managed=True)
            self.set_status(store, bid, "queued")
            self._mf_update(slug, sha, state="queued", error=None)
            with self._lock:
                self._jobs[(slug, bid)] = job
            threading.Thread(target=self._run_managed, args=(job,), name=f"airlock-dotnet-{name}",
                             daemon=True).start()
            return job
        program = (store.get_meta(f"program:{bid}") if existing is not None else None) \
            or self._free_program_name(store, name, sha)
        store.set_meta(f"program:{bid}", program)
        job = Job(slug, bid, program, artifact, paths, sha256=sha, rel_path=rel_path,
                  group=group, code_size=int(code_size or 0), est_funcs=est_funcs,
                  seq=next(self._seq))
        self.set_status(store, bid, "queued")
        self._mf_update(slug, sha, state="queued", error=None)  # before the job can advance
        with self._lock:
            self._jobs[(slug, bid)] = job
            self._by_program[program] = job
            self._queue.append(job)
            self._ensure_runner()
        return job

    @staticmethod
    def _free_program_name(store: Store, name: str, sha: str) -> str:
        """Slug of the file name; two files with the same name in one project get a sha suffix."""
        base = program_name_for(name)
        used = {r["value"] for r in store.db.execute(
            "SELECT value FROM meta WHERE key LIKE 'program:%'")}
        return base if base not in used else f"{base}_{sha[:6]}"

    def _ensure_runner(self) -> None:
        with self._lock:
            if self._runner is None or not self._runner.is_alive():
                self._runner = threading.Thread(target=self._run_queue, name="airlock-queue",
                                                daemon=True)
                self._runner.start()

    def _next_job(self) -> Job | None:
        with self._lock:
            if not self._queue:
                self._running = None
                self._runner = None
                return None
            job = min(self._queue, key=lambda j: j.priority)
            self._queue.remove(job)
            self._running = job
            return job

    def _run_queue(self) -> None:
        """The one queue thread: one binary at a time, import -> analyse -> extract."""
        while True:
            job = self._next_job()
            if job is None:
                return
            try:
                job.started = time.monotonic()
                self._run_job(job)
                while not job.finished.wait(2.0):
                    if not self.worker.running():
                        self._fail(job, "worker stopped while the binary was being processed; "
                                        "a server restart resumes it")
                        break
            except Exception as e:  # keep the queue alive
                self._fail(job, f"{type(e).__name__}: {e}")

    # -- manifest ------------------------------------------------------------

    def _mf_update(self, project: str, sha: str, **fields: Any) -> None:
        """Set (or, with None, remove) fields on the manifest file entries with this sha256."""
        paths = self.paths(project)
        with self._mf_lock:
            try:
                man = read_manifest(paths.manifest)
            except (OSError, ValueError):
                return
            hit = False
            for f in man.get("files") or []:
                if f.get("sha256") == sha:
                    hit = True
                    for k, v in fields.items():
                        if v is None:
                            f.pop(k, None)
                        else:
                            f[k] = v
            if hit:
                write_manifest(paths.manifest, man)

    def _state(self, job: Job, status: str, error: str | None = None, **manifest: Any) -> None:
        """Binary status in the index and the manifest entry state, together."""
        self.set_status(self.store(job.project), job.binary_id, status, error)
        self._plog(job).log(logging.WARNING if error else logging.INFO, "queue: %s -> %s%s", job.program,
                            status, f" ({error})" if error else "")
        self._mf_update(job.project, job.sha256, state=status, error=error or None, **manifest)

    def _plog(self, job: Job) -> logging.LoggerAdapter:
        return logs.project_log(self.paths(job.project).logs)

    def model(self, files: list[dict[str, Any]]) -> tuple[float, float]:
        """(overhead_s, s_per_mb): the configured priors refined by the measured entries."""
        prior_oh, prior_rate = est.priors(self.config.defaults)
        samples = []
        for f in files:
            secs = f.get("total_s")
            if secs is None and f.get("analysis_s"):
                secs = float(f["analysis_s"]) + float(f.get("extract_s") or 0.0)
            if secs and f.get("code_size") is not None:
                samples.append((est.work_mb(f["code_size"], f.get("est_funcs") or 0), float(secs)))
        return est.refine(samples, prior_oh, prior_rate)

    def s_per_mb(self, files: list[dict[str, Any]]) -> float:
        return self.model(files)[1]

    def decompile_estimate(self, project: str, files: list[dict[str, Any]],
                           pending_code: float) -> tuple[int, float]:
        """(functions still to decompile in the background pass, seconds at the measured rate).
        Binaries not extracted yet count with the project's functions per code MB."""
        if not self.bulk.enabled:
            return 0, 0.0
        st = self.store(project)
        by_sha = {f.get("sha256"): f for f in files}
        fns = 0
        known_fns = known_mb = 0.0
        rate = 0.0
        for b in st.list_binaries():
            f = by_sha.get(b.sha256, {})
            if (f.get("group") in SKIP_GROUPS or b.format == "dotnet"
                    or self.get_status(st, b.id)[0] != "ready"):
                continue
            target = st.decomp_target_count(b.id)
            known_fns += target
            known_mb += float(f.get("code_size") or 0) / _MB
            fns += max(target - st.decomp_current_count(b.id, b.analysis_profile or "unknown"), 0)
            bp = self.bulk.progress(project, b.id)
            if bp is not None and bp.rate > 0:
                rate = bp.rate
        if known_mb > 0 and pending_code > 0:
            fns += int(known_fns / known_mb * pending_code / _MB)
        rate = rate or DECOMPILE_FN_PER_S
        return fns, fns / rate

    def queue_status(self, project: str) -> QueueStatus:
        """Rows for every binary of the project and the refined remaining-time estimate."""
        store = self.store(project)
        try:
            man = read_manifest(self.paths(project).manifest)
        except (OSError, ValueError):
            man = {}
        files = man.get("files") or []
        by_sha = {f.get("sha256"): f for f in files}
        overhead, rate = self.model(files)
        with self._lock:
            waiting = sorted((j for j in self._queue if j.project == project),
                             key=lambda j: j.priority)
            running = self._running if self._running and self._running.project == project else None
        order = {j.binary_id: i for i, j in enumerate(waiting)}
        now = time.monotonic()
        rows: list[QueueRow] = []
        remaining = over = pending_code = 0.0
        for b in store.list_binaries():
            status, _ = self.get_status(store, b.id)
            f = by_sha.get(b.sha256, {})
            job = self.job_for(project, b.id)
            code = int(f.get("code_size") or (job.code_size if job else 0) or 0)
            work = est.work_mb(code, f.get("est_funcs") or (job.est_funcs if job else 0) or 0)
            est_s = MANAGED_S if b.format == "dotnet" else est.binary_seconds(work, overhead, rate)
            secs: float | None = None
            e: float | None = est_s
            if status == "ready":
                secs, e = f.get("analysis_s"), None
            elif status == "error":
                e = None
            elif job is not None and job is running:
                secs = now - job.started
                remaining += max(est_s - secs, est.RUNNING_FLOOR * est_s)
                over = max(secs - est_s, 0.0)
                pending_code += code
            elif b.id in order or status == "queued":
                remaining += est_s
                pending_code += code
            rows.append(QueueRow(b.id, b.name, status, secs, e, code))

        def key(r: QueueRow) -> tuple:
            if running is not None and r.binary_id == running.binary_id:
                return (0, 0, r.binary_id)
            if r.binary_id in order:
                return (1, order[r.binary_id], r.binary_id)
            return (2 if r.state not in FINAL else 3, 0, r.binary_id)

        rows.sort(key=key)
        cur = next((r for r in rows if running is not None and r.binary_id == running.binary_id), None)
        fns, dec_s = self.decompile_estimate(project, files, pending_code)
        return QueueStatus(tuple(rows), remaining, rate, cur, overhead, over, fns, dec_s)

    # -- job: import -> analyse -> extract ------------------------------------

    def _link_libs(self, st: Store, exclude: int, statuses: tuple[str, ...]) -> dict[str, str]:
        """{dll file name (lower): program name} of the project's binaries in these statuses;
        names that occur twice are left out (ambiguous)."""
        seen: dict[str, list[str]] = {}
        for b in st.list_binaries():
            if b.id != exclude and b.format != "dotnet" and self.get_status(st, b.id)[0] in statuses:
                seen.setdefault(b.name.lower(), []).append(self.program_of(st, b))
        return {n: p[0] for n, p in seen.items() if len(p) == 1}

    def _link_externals(self, links: list[dict[str, Any]]) -> None:
        """Point external library paths at project programs; never fails a binary."""
        links = [x for x in links if x["libs"]]
        if not links:
            return
        try:
            self.worker.request("link_externals", {"links": links}, timeout=300)
        except WorkerError as e:
            log.warning("link_externals failed: %s", e)

    def _run_job(self, job: Job) -> None:
        w = self.worker
        st = self.store(job.project)
        bid = job.binary_id
        try:
            self._state(job, "importing")
            with self._switch:
                w.ensure_ghidra()
                w.request("open_project", {"path": str(job.paths.ghidra), "name": GHIDRA_PROJECT_NAME},
                          timeout=300)
            # "project" makes the worker refuse the request if the open project was switched since
            imp = w.request("import_binary", {"artifact_path": str(job.artifact),
                                              "program_name": job.program,
                                              "project": str(job.paths.ghidra)}, timeout=1800)
            if imp.get("pointer_size") is None or imp.get("image_base") is None:
                raise WorkerError("import_failed", f"the import of {job.program} produced no program")
            b = st.get_binary_by_id(bid)
            assert b is not None
            st.upsert_binary(b.sha256, b.name, pointer_size=imp.get("pointer_size"),
                             image_base=imp.get("image_base"))
            # imports of programs already in the project resolve to them before analysis
            self._link_externals([{"program": job.program, "libs": self._link_libs(
                st, bid, ("analysing", "extracting") + USABLE)}])
            job.analysis_started = time.monotonic()
            self._state(job, "analysing")
            job.reached.set()
            res = w.request("analyze", {
                "program": job.program, "project": str(job.paths.ghidra),
                "timeout_min": self.config.defaults.get("analysis_timeout_min"),
                "parameter_id": bool(self.config.defaults.get("decompiler_parameter_id", True)),
            }, timeout=300)
            if res.get("already_analysed") or res.get("state") == "ready":
                job.already_analysed = bool(res.get("already_analysed"))
                self._start_extract(job)
        except WorkerError as e:
            self._fail(job, worker_error(e))
        except Exception as e:  # never leave a job silently stuck
            self._fail(job, f"{type(e).__name__}: {e}")

    def _run_managed(self, job: Job) -> None:
        """An IL-only assembly: read the metadata with dnfile (seconds), no Ghidra, no queue."""
        st = self.store(job.project)
        bid = job.binary_id
        try:
            self._state(job, "extracting")
            t0 = time.monotonic()
            b = st.get_binary_by_id(bid)
            assert b is not None
            dotnet.ensure(st, b, job.artifact, force=True)
            if not st.db.execute("SELECT 1 FROM dn_type WHERE binary_id=? LIMIT 1", (bid,)).fetchone():
                raise ValueError("no .NET metadata found")
            st.upsert_binary(b.sha256, b.name, analysed_at=_now())
            self._state(job, "finishing", code_size=0, managed=True,
                        extract_s=round(time.monotonic() - t0, 2))
        except Exception as e:  # noqa: BLE001
            self._fail(job, f"cannot read .NET metadata: {type(e).__name__}: {e}")
            return
        try:
            self._after_managed(job)
        except Exception as e:  # noqa: BLE001  links are an extra; the binary becomes ready
            self._plog(job).warning("linking failed for %s: %s", job.program, e)
        self._ready(job)
        job.reached.set()
        job.finished.set()

    def _after_managed(self, job: Job) -> None:
        """Resources, then P/Invoke links to the other ready binaries (and theirs to this one)."""
        st = self.store(job.project)
        me = st.get_binary_by_id(job.binary_id)
        assert me is not None
        job.step = "tables"
        try:
            peres.ensure(st, me, self.paths(job.project).artifacts / me.sha256)
        except Exception as e:  # noqa: BLE001  an extra
            self._plog(job).warning("resources of %s: %s", me.name, e)
        job.step = "links"
        others = [b.id for b in st.list_binaries()
                  if b.id != me.id and self.get_status(st, b.id)[0] in USABLE]
        st.link_cross_binary(me.id, others)
        job.step = "features"
        self._fire_ready(job.project, me.id, job.program)

    def _fail(self, job: Job, message: str) -> None:
        self._state(job, "error", message)
        job.reached.set()
        job.finished.set()

    # -- events / extraction -----------------------------------------------

    def _on_event(self, msg: dict[str, Any]) -> None:
        """Runs on the worker client's reader thread: must not call the worker."""
        if msg.get("event") != "progress" or msg.get("job") != "analysis":
            return
        job = self._by_program.get(msg.get("program") or "")
        if job is None:
            return
        state = msg.get("state")
        if state == "done":
            self._start_extract(job)
        elif state in ("error", "cancelled"):
            threading.Thread(
                target=self._fail,
                args=(job, f"analysis {state}: {msg.get('message') or ''}".strip()),
                daemon=True).start()

    def _start_extract(self, job: Job) -> None:
        with job.lock:
            if job.extracting:
                return
            job.extracting = True
        threading.Thread(target=self._extract_job, args=(job,), name=f"airlock-extract-{job.program}",
                         daemon=True).start()

    def _extract_job(self, job: Job) -> None:
        st = self.store(job.project)
        bid = job.binary_id
        try:
            analysis_s = None
            if job.analysis_started is not None and not job.already_analysed:
                analysis_s = round(time.monotonic() - job.analysis_started, 1)
            self._state(job, "extracting")
            t0 = time.monotonic()
            res = run_extraction(self.worker, st, bid, job.program, artifact=job.artifact,
                                 project=str(job.paths.ghidra))
            job.timings = {**{f"extract_{k}": v for k, v in res["secs"].items()},
                           "extract_total": round(time.monotonic() - t0, 2)}
            profile = collector = None
            try:
                s = self.worker.request("status", {"program": job.program}, timeout=30)
                profile = (s.get("programs") or [{}])[0].get("analysis_profile")
                collector = (s.get("programs") or [{}])[0].get("collector")
            except WorkerError:
                pass
            b = st.get_binary_by_id(bid)
            assert b is not None
            st.upsert_binary(b.sha256, b.name, pointer_size=res["pointer_size"],
                             image_base=res["image_base"], analysis_profile=profile,
                             analysed_at=_now())
            if collector is not None:
                st.set_meta(f"collector:{bid}", str(collector))
            extra: dict[str, Any] = {"code_size": job.code_size, "est_funcs": job.est_funcs or None,
                                     "extract_s": job.timings["extract_total"]}
            if analysis_s is not None:
                extra["analysis_s"] = analysis_s
                if job.started is not None:
                    extra["total_s"] = round(time.monotonic() - job.started, 1)
            self._state(job, "finishing", **extra)
        except WorkerError as e:
            self._fail(job, worker_error(e))
            return
        except Exception as e:
            self._fail(job, f"extraction failed: {type(e).__name__}: {e}")
            return
        try:
            self._after_ready(job)
        except Exception as e:  # links are an extra; the binary becomes ready
            self._plog(job).warning("cross-binary linking failed for %s: %s", job.program, e)
        self._ready(job)
        job.reached.set()
        try:
            self.bulk.schedule(job.project, job.binary_id, job.group)
        except Exception as e:  # the pass is an extra; the binary stays ready
            self._plog(job).warning("cannot schedule the decompile pass for %s: %s", job.program, e)
        job.finished.set()

    def _ready(self, job: Job) -> None:
        """End of the index work (status finishing -> ready); the decompile pass comes after."""
        job.step = ""
        try:
            self._state(job, "ready")
        except Exception as e:  # noqa: BLE001
            self._plog(job).warning("cannot publish ready for %s: %s", job.program, e)

    def _after_ready(self, job: Job) -> None:
        """Refine the s/MB estimate, then link this binary with the project's other ready ones:
        index edges (import slot/thunk -> exporting function) and Ghidra external paths of the
        earlier programs that import this one."""
        st = self.store(job.project)
        bid = job.binary_id
        with self._mf_lock:
            try:
                man = read_manifest(self.paths(job.project).manifest)
            except (OSError, ValueError):
                man = None
            if man is not None and man.get("files"):
                oh, rate = self.model(man["files"])
                man["queue"] = {"s_per_mb": round(rate, 1), "overhead_s": round(oh, 1)}
                write_manifest(self.paths(job.project).manifest, man)
        me = st.get_binary_by_id(bid)
        assert me is not None
        job.step = "tables"
        others = [b for b in st.list_binaries()
                  if b.id != bid and self.get_status(st, b.id)[0] in USABLE]
        if me.toolchain == "dotnet":    # mixed-mode: native code through Ghidra, plus the metadata
            try:
                dotnet.ensure(st, me, self.paths(job.project).artifacts / me.sha256, force=True)
            except Exception as e:  # noqa: BLE001  metadata is an extra
                self._plog(job).warning(".NET metadata of %s: %s", me.name, e)
        try:
            linking.fix_export_ordinals(st, me, self.paths(job.project).artifacts / me.sha256)
        except Exception as e:  # noqa: BLE001  ordinals are an extra
            self._plog(job).warning("export ordinals of %s: %s", me.name, e)
        try:
            peres.ensure(st, me, self.paths(job.project).artifacts / me.sha256)
        except Exception as e:  # noqa: BLE001  resources are an extra
            self._plog(job).warning("resources of %s: %s", me.name, e)
        cpp.ensure(st, me, self.paths(job.project).artifacts / me.sha256)   # RTTI, vtables, message maps
        delphi.ensure(st, me, self.paths(job.project).artifacts / me.sha256, self.config.idr_kb_dir,
                         self.config.delphi_sigdb_dir, self.config.warp_dir)   # VMTs, published methods, DFM, IDR names
        qt.ensure(st, me, self.paths(job.project).artifacts / me.sha256)   # QMetaObjects, string connects
        job.step = "functions"
        try:
            self.create_missing_functions(job.project, st, me, progress=self._fn_progress(job))   # handlers, vtable targets
        except Exception as e:  # noqa: BLE001  an extra; the binary becomes ready
            self._plog(job).warning("missing functions of %s: %s", me.name, e)
        delphi.ensure(st, me, self.paths(job.project).artifacts / me.sha256, self.config.idr_kb_dir,
                         self.config.delphi_sigdb_dir, self.config.warp_dir)   # IDR names: the function list may have grown
        job.step = "Qt dispatch"
        try:
            qt.resolve(self, job.project, st, me)   # Qt method addresses, imported parents
        except Exception as e:  # noqa: BLE001  an extra; the binary stays ready
            self._plog(job).warning("Qt dispatch of %s: %s", me.name, e)
        job.step = "links"
        st.link_cross_binary(bid, [b.id for b in others])
        try:
            linking.link_dynamic_for(st, bid, [b.id for b in others])
        except Exception as e:  # noqa: BLE001  dynamic links are an extra
            self._plog(job).warning("dynamic links of %s: %s", me.name, e)
        links = []
        for o in others:
            if o.format == "dotnet":
                continue
            if any(True for _ in st.db.execute(
                    "SELECT 1 FROM import WHERE binary_id=? AND lower(dll)=? LIMIT 1",
                    (o.id, me.name.lower()))):
                links.append({"program": self.program_of(st, o), "libs": {me.name.lower(): job.program}})
        self._link_externals(links)
        job.step = "features"
        self._fire_ready(job.project, bid, job.program)

    @staticmethod
    def _fn_progress(job: Job) -> Callable[[int, int], None]:
        def say(done: int, total: int) -> None:
            job.step = f"functions {done}/{total}"
        return say

    def _fire_ready(self, project: str, bid: int, what: str = "") -> None:
        """Run the ready hooks (feature derivation + project map) for ``project``."""
        for hook in list(self.ready_hooks):
            try:
                hook(project, bid)
            except Exception as e:  # a hook is an extra; the binary stays ready
                logs.project_log(self.paths(project).logs).warning("ready hook failed for %s: %s", what or project, e)

    # -- worker session for decompile --------------------------------------

    def ensure_open(self, project: str) -> None:
        """Make sure the worker has Ghidra running and this project open (the worker
        may have been restarted since open_binary). Raises WorkerError."""
        w = self.worker
        slug = slugify(project)
        with self._switch:
            # The queue job owns the worker's open project from its import to its last step;
            # switching it away would make the job import into or read from the wrong project.
            with self._lock:
                job = self._running
            if job is not None and job.project != slug and not job.finished.is_set():
                raise WorkerError("busy", f"the worker is indexing project '{job.project}' "
                                          f"({job.program})")
            w.ensure_ghidra()
            s = w.request("status", timeout=30)
            paths = self.paths(project)
            cur = s.get("project")
            if not cur or Path(cur["path"]) != paths.ghidra or cur["name"] != GHIDRA_PROJECT_NAME:
                w.request("open_project", {"path": str(paths.ghidra), "name": GHIDRA_PROJECT_NAME},
                          timeout=300)

    def _other_busy(self, slug: str) -> bool:
        """True while the queue holds a running or waiting job of another project."""
        with self._lock:
            jobs = [self._running] if self._running is not None else []
            return any(j.project != slug for j in (*jobs, *self._queue))
