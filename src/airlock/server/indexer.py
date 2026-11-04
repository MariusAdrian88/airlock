"""Indexing orchestration (DESIGN.md section 5), server side. Never imports pyghidra.

open_binary: detect + hash + copy + register (status ``queued``), then a job
thread drives the worker: ensure_ghidra, open_project, import_binary, analyze.
When the worker reports analysis ``done``, a second thread pages through the
``extract`` kinds into the project's Store, links edges, rebuilds the FTS table
and sets the binary ``ready``.

Binary status lives in the index ``meta`` table (``status:<id>``), so it survives
a server restart: queued -> importing -> analysing -> extracting -> ready | error.
A persisted non-final status with no live job means the server stopped mid-way;
open_binary on the same file resumes it.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from airlock.config import Config
from airlock.index.store import Binary, Store
from airlock.projects import (
    ProjectPaths, copy_artifact, detect, hash_file, list_projects, project_paths, slugify,
)
from airlock.worker.protocol import WorkerError

GHIDRA_PROJECT_NAME = "airlock"
EXTRACT_KINDS = ("functions", "imports", "strings", "edges")
PAGE_SIZE = {"functions": 5000, "imports": 5000, "strings": 5000, "edges": 10000}
FINAL = ("ready", "error")
OPEN_WAIT_S = 30.0


class IndexerError(Exception):
    """Carries a ready-to-return one-line error in project format (.message)."""

    def __init__(self, code: str, what: str, action: str) -> None:
        self.code = code
        self.message = f"error {code}: {what}. {action}."
        super().__init__(self.message)


def worker_error(e: WorkerError, action: str = "Check logs\\worker.log or call index_status") -> str:
    msg = e.message.rstrip(". ")
    return f"error {e.code}: {msg}. {action}."


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
                   on_kind: Callable[[str, int], None] | None = None) -> dict[str, Any]:
    """Page through all four kinds into ``store``; returns counts, timings, image
    base and pointer size. Idempotent: derived rows are cleared first."""
    store.clear_binary_data(binary_id)
    counts: dict[str, int] = {}
    secs: dict[str, float] = {}
    image_base = pointer_size = None
    for kind in EXTRACT_KINDS:
        t0 = time.monotonic()
        offset, n = 0, 0
        while True:
            r = worker.request("extract", {"program": program, "kind": kind, "offset": offset,
                                           "limit": PAGE_SIZE[kind]}, timeout=900)
            image_base, pointer_size = r.get("image_base"), r.get("pointer_size")
            cols, rows = r["columns"], r["rows"]
            if kind == "functions":
                store.insert_functions(binary_id, map_function_rows(cols, rows))
            elif kind == "imports":
                store.insert_imports(binary_id, map_import_rows(cols, rows))
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
        self._lock = threading.Lock()
        worker.on_event(self._on_event)

    # -- stores / projects -------------------------------------------------

    def paths(self, project: str, create: bool = False) -> ProjectPaths:
        return project_paths(self.config.data_dir, project, create=create)

    def store(self, project: str) -> Store:
        """This thread's Store for the project (sqlite connections are per thread)."""
        slug = slugify(project)
        stores = self._tls.__dict__.setdefault("stores", {})
        st = stores.get(slug)
        if st is None:
            st = stores[slug] = Store(self.paths(slug, create=True).index_db)
        return st

    def projects(self) -> list[str]:
        return list_projects(self.config.data_dir)

    def resolve_project(self, project: str | None = None) -> str:
        """Explicit project, else the last opened one, else the only one on disk."""
        if project:
            slug = slugify(project)
            if slug not in self.projects():
                raise IndexerError("no_project", f"project '{project}' does not exist",
                                   "Call open_binary with this project name to create it")
            return slug
        if self.current:
            return self.current
        known = self.projects()
        if len(known) == 1:
            return known[0]
        if not known:
            raise IndexerError("no_project", "no project exists yet",
                               "Call open_binary with a project name and a file path")
        raise IndexerError("ambiguous_project", f"{len(known)} projects exist: {', '.join(known)}",
                           "Call open_binary on one of them first")

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
        if job is None:
            return "interrupted", (f"was {status} when the server stopped. "
                                   "Call open_binary on the file again to resume")
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
        if status == "ready":
            return None
        if status == "error":
            return (f"error not_analysed: binary '{b.name}' failed to index ({detail}). "
                    "Fix the cause and call open_binary again.")
        return (f"error not_analysed: binary '{b.name}' is {status} ({detail}). "
                "Retry later or call index_status.")

    # -- open_binary -------------------------------------------------------

    def open_binary(self, project: str, path: str, wait_s: float = OPEN_WAIT_S) -> OpenResult:
        src = Path(path).expanduser()
        if not src.is_file():
            raise IndexerError("not_found", f"file '{path}' does not exist",
                               "Pass the full path of a PE file")
        info = detect(src)
        if info.format == "not-pe":
            raise IndexerError("unsupported", f"'{src.name}' is not a PE file",
                               "airlock opens Windows PE executables and DLLs")
        if info.toolchain == "dotnet":
            raise IndexerError("unsupported", f"'{src.name}' is a .NET assembly",
                               "The .NET path is not implemented yet")
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
        sha, artifact = copy_artifact(src, paths, sha)
        program = program_name_for(src.name)
        bid = store.upsert_binary(
            sha, src.name, original_path=str(src), format=info.format, arch=info.arch,
            pointer_size=info.pointer_size, image_base=info.image_base,
            toolchain=info.toolchain, imported_at=_now(),
        )
        store.set_meta(f"program:{bid}", program)
        self.set_status(store, bid, "queued")
        job = Job(paths.name, bid, program, artifact, paths)
        with self._lock:
            self._jobs[(paths.name, bid)] = job
            self._by_program[program] = job
        threading.Thread(target=self._run_job, args=(job,), name=f"airlock-open-{program}",
                         daemon=True).start()
        job.reached.wait(wait_s)
        b = store.get_binary_by_id(bid)
        assert b is not None
        status, _ = self.get_status(store, bid)
        note = "resumed after restart" if existing is not None else None
        return OpenResult(b, status, note)

    def _run_job(self, job: Job) -> None:
        w = self.worker
        st = self.store(job.project)
        bid = job.binary_id
        try:
            self.set_status(st, bid, "importing")
            w.ensure_ghidra()
            w.request("open_project", {"path": str(job.paths.ghidra), "name": GHIDRA_PROJECT_NAME},
                      timeout=300)
            imp = w.request("import_binary", {"artifact_path": str(job.artifact),
                                              "program_name": job.program}, timeout=1800)
            b = st.get_binary_by_id(bid)
            assert b is not None
            st.upsert_binary(b.sha256, b.name, pointer_size=imp.get("pointer_size"),
                             image_base=imp.get("image_base"))
            self.set_status(st, bid, "analysing")
            job.reached.set()
            res = w.request("analyze", {
                "program": job.program,
                "timeout_min": self.config.defaults.get("analysis_timeout_min"),
            }, timeout=300)
            if res.get("already_analysed") or res.get("state") == "ready":
                self._start_extract(job)
        except WorkerError as e:
            self._fail(job, worker_error(e))
        except Exception as e:  # never leave a job silently stuck
            self._fail(job, f"{type(e).__name__}: {e}")

    def _fail(self, job: Job, message: str) -> None:
        self.set_status(self.store(job.project), job.binary_id, "error", message)
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
            self.set_status(st, bid, "extracting")
            t0 = time.monotonic()
            res = run_extraction(self.worker, st, bid, job.program)
            job.timings = {**{f"extract_{k}": v for k, v in res["secs"].items()},
                           "extract_total": round(time.monotonic() - t0, 2)}
            profile = None
            try:
                s = self.worker.request("status", {"program": job.program}, timeout=30)
                profile = (s.get("programs") or [{}])[0].get("analysis_profile")
            except WorkerError:
                pass
            b = st.get_binary_by_id(bid)
            assert b is not None
            st.upsert_binary(b.sha256, b.name, pointer_size=res["pointer_size"],
                             image_base=res["image_base"], analysis_profile=profile,
                             analysed_at=_now())
            self.set_status(st, bid, "ready")
        except WorkerError as e:
            self._fail(job, worker_error(e))
            return
        except Exception as e:
            self._fail(job, f"extraction failed: {type(e).__name__}: {e}")
            return
        job.reached.set()
        job.finished.set()

    # -- worker session for decompile --------------------------------------

    def ensure_open(self, project: str) -> None:
        """Make sure the worker has Ghidra running and this project open (the worker
        may have been restarted since open_binary). Raises WorkerError."""
        w = self.worker
        w.ensure_ghidra()
        s = w.request("status", timeout=30)
        paths = self.paths(project)
        cur = s.get("project")
        if not cur or Path(cur["path"]) != paths.ghidra or cur["name"] != GHIDRA_PROJECT_NAME:
            w.request("open_project", {"path": str(paths.ghidra), "name": GHIDRA_PROJECT_NAME},
                      timeout=300)
