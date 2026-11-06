"""Background decompile pass (DESIGN.md section 5 step 8), server side. Never imports pyghidra.

When a binary is `ready` and defaults.bulk_decompile is "background", the scheduler decompiles
all its functions that are not thunks or externals, and caches the results in the index
(`decomp` + `ast_node`, with fn_version and analysis_profile exactly as the `function` tool
writes them). One binary at a time, on one thread:

1. wait until the analysis queue is idle (analysis has priority; a pass that is already
   running keeps going and the worker lowers it to the minimum CPU share while an analysis
   runs, see worker.pool);
2. plan: candidates without a valid cache row, feature entry points first, then by caller
   count, then by address;
3. send the worker one `bulk_decompile` request with the order, then write the
   `decompile_results` events it emits to the index in batches until the terminal
   `decompile_progress` event.

Runtime-group binaries are skipped. The pass resumes after a server restart through
`Indexer.resume_project` (only functions without a valid row are planned).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from airlock.index.store import is_transient_decomp_error
from airlock.projects import read_manifest, slugify
from airlock.worker.protocol import WorkerError

log = logging.getLogger("airlock")

SKIP_GROUPS = ("runtime",)
TERMINAL = ("done", "cancelled", "error", "interrupted")
IDLE_POLL_S = 1.0
EVENT_WAIT_S = 2.0
BG_TIMEOUT = "bg_timeout"  # error prefix of a timeout row written by the background pass
MAX_REQUEUE = 3  # a pass that lost results to a worker failure or a project switch is queued again
STALL_S = 180.0  # no event for this long while the worker lives: the pass is stuck


@dataclass(frozen=True)
class BulkProgress:
    state: str            # waiting | planning | running | done | cancelled | error | interrupted
    done: int = 0
    total: int = 0
    rate: float = 0.0
    threads: int = 0
    processors: int = 0
    ok: int = 0
    failed: int = 0
    message: str = ""


@dataclass(frozen=True)
class _Item:
    project: str
    binary_id: int
    program: str = ""


def order_candidates(rows: list[Any], feature_ids: set[int]) -> list[Any]:
    """Feature entry points first, then most called, then by address. `rows` have id, entry,
    callers (sqlite rows or dicts)."""
    return sorted(rows, key=lambda r: (0 if r["id"] in feature_ids else 1,
                                       -int(r["callers"] or 0), r["entry"]))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BulkScheduler:
    def __init__(self, indexer: Any) -> None:
        self.ix = indexer
        self._lock = threading.RLock()
        self._pending: list[_Item] = []
        self._current: _Item | None = None
        self._thread: threading.Thread | None = None
        self._progress: dict[tuple[str, int], BulkProgress] = {}
        self._cancelled: set[tuple[str, int]] = set()
        self._requeued: dict[tuple[str, int], int] = {}
        self._events: queue.Queue[dict[str, Any]] = queue.Queue()
        indexer.worker.on_event(self._on_event)

    # -- config -------------------------------------------------------------

    @property
    def mode(self) -> str:
        return str(self.ix.config.defaults.get("bulk_decompile") or "background")

    @property
    def enabled(self) -> bool:
        return self.mode == "background"

    # -- public -------------------------------------------------------------

    def schedule(self, project: str, binary_id: int, group: str | None = None) -> bool:
        """Queue a pass for a ready binary. False when disabled, skipped (runtime group) or
        already queued/running."""
        if not self.enabled or (group or "") in SKIP_GROUPS:
            return False
        key = (project, binary_id)
        with self._lock:
            if self._current and (self._current.project, self._current.binary_id) == key:
                return False
            if any((i.project, i.binary_id) == key for i in self._pending):
                return False
            self._cancelled.discard(key)
            self._pending.append(_Item(project, binary_id))
            self._progress[key] = BulkProgress("waiting")
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._loop, name="airlock-bulk", daemon=True)
                self._thread.start()
        return True

    def resume(self, project: str) -> int:
        """Schedule the ready, non-runtime binaries of the project that still have undecompiled
        functions. Returns how many were scheduled."""
        if not self.enabled:
            return 0
        ix = self.ix
        st = ix.store(project)
        try:
            man = read_manifest(ix.paths(project).manifest)
        except (OSError, ValueError):
            man = {}
        groups = {f.get("sha256"): f.get("group") for f in man.get("files") or []}
        n = 0
        st.purge_transient_decomp()      # rows of older versions: worker failures stored as results
        for b in st.list_binaries():
            if ix.get_status(st, b.id)[0] != "ready":
                continue
            profile = b.analysis_profile or "unknown"
            if st.decomp_current_count(b.id, profile) >= st.decomp_target_count(b.id):
                continue
            n += self.schedule(project, b.id, groups.get(b.sha256))
        return n

    def progress(self, project: str, binary_id: int) -> BulkProgress | None:
        return self._progress.get((project, binary_id))

    def active(self) -> bool:
        with self._lock:
            return bool(self._pending) or self._current is not None

    def cancel(self, project: str, binary_id: int) -> bool:
        key = (project, binary_id)
        with self._lock:
            self._cancelled.add(key)
            before = len(self._pending)
            self._pending = [i for i in self._pending if (i.project, i.binary_id) != key]
            was_pending = len(self._pending) != before
            current = self._current is not None and (
                self._current.project, self._current.binary_id) == key
            program = self._current.program if current and self._current else ""
        if was_pending:
            self._progress[key] = BulkProgress("cancelled")
        if current and program:
            try:
                self.ix.worker.request("cancel_bulk", {"program": program}, timeout=30)
            except WorkerError:
                pass
        return was_pending or current

    def wait_idle(self, timeout: float = 60.0) -> bool:
        """Block until no pass is queued or running (tests, shutdown)."""
        end = time.monotonic() + timeout
        while self.active():
            if time.monotonic() > end:
                return False
            time.sleep(0.02)
        return True

    # -- events -------------------------------------------------------------

    def _on_event(self, msg: dict[str, Any]) -> None:
        """Reader thread: just hand over. Writing to sqlite happens on the pass thread."""
        if msg.get("event") in ("decompile_results", "decompile_progress"):
            self._events.put(msg)

    # -- the pass thread ----------------------------------------------------

    def _loop(self) -> None:
        while True:
            with self._lock:
                if not self._pending:
                    self._current = None
                    self._thread = None
                    return
                item = next((i for i in self._pending if self._may_run(i)), None)
                if item is not None:
                    self._pending.remove(item)
                    self._current = item
            if item is None:    # only projects other than the bound one wait: do not switch the worker
                time.sleep(IDLE_POLL_S)
                continue
            key = (item.project, item.binary_id)
            try:
                self._run(item)
            except WorkerError as e:
                log.warning("bulk decompile of binary %s failed: %s", item.binary_id, e)
                self._progress[key] = BulkProgress("error", message=f"{e.code}: {e.message}")
            except Exception as e:  # never kill the scheduler
                log.warning("bulk decompile of binary %s failed: %s: %s",
                            item.binary_id, type(e).__name__, e)
                self._progress[key] = BulkProgress("error", message=f"{type(e).__name__}: {e}")

    def _may_run(self, item: _Item) -> bool:
        """A session bound to a project owns the worker's open project: the pass runs only for that
        project (opening another one closes the programs the session works on)."""
        cur = getattr(self.ix, "current", None)
        return not cur or slugify(cur) == item.project

    def _requeue(self, key: tuple[str, int]) -> None:
        n = self._requeued.get(key, 0)
        if n >= MAX_REQUEUE or key in self._cancelled:
            return
        self._requeued[key] = n + 1
        with self._lock:    # the running pass is this key: schedule() would refuse it
            if not any((i.project, i.binary_id) == key for i in self._pending):
                self._pending.append(_Item(key[0], key[1]))
                self._progress[key] = BulkProgress("waiting")

    def _wait_queue_idle(self, key: tuple[str, int]) -> bool:
        while not self.ix.queue_idle():
            if key in self._cancelled:
                return False
            time.sleep(IDLE_POLL_S)
        return key not in self._cancelled

    def plan(self, st: Any, binary_id: int, profile: str) -> list[Any]:
        rows = st.decomp_candidates(binary_id, profile)
        return order_candidates(rows, st.feature_entry_function_ids(binary_id))

    def _run(self, item: _Item) -> None:
        ix = self.ix
        key = (item.project, item.binary_id)
        if not self._wait_queue_idle(key):
            self._progress[key] = BulkProgress("cancelled")
            return
        st = ix.store(item.project)
        b = st.get_binary_by_id(item.binary_id)
        if b is None or ix.get_status(st, b.id)[0] != "ready":
            self._progress.pop(key, None)
            return
        self._progress[key] = BulkProgress("planning")
        profile = b.analysis_profile or "unknown"
        st.purge_transient_decomp()
        rows = self.plan(st, b.id, profile)
        if not rows:
            self._progress[key] = BulkProgress("done")
            return
        by_entry = {int(r["entry"]): (int(r["id"]), int(r["version"])) for r in rows}
        program = ix.program_of(st, b)
        item = _Item(item.project, item.binary_id, program)
        with self._lock:
            self._current = item
        d = ix.config.defaults
        ix.ensure_open(item.project)
        while True:  # drop events of earlier passes
            try:
                self._events.get_nowait()
            except queue.Empty:
                break
        res = ix.worker.request("bulk_decompile", {
            "program": program, "order": [int(r["entry"]) for r in rows],
            "timeout": int(d.get("bulk_decompile_timeout_s") or 15),
            "cpu_min": d.get("decompile_cpu_min"), "cpu_max": d.get("decompile_cpu_max"),
        }, timeout=300)
        job = res.get("job")
        total = len(rows)
        self._progress[key] = BulkProgress("running", total=total,
                                           threads=int(res.get("threads") or 0),
                                           processors=int(res.get("processors") or 0))
        if key in self._cancelled:
            self.cancel(*key)
        lost, state = self._consume(item, st, profile, by_entry, job, total)
        # results lost to a worker failure, or the pass cut by a project switch: plan the rest again
        if (lost or state == "cancelled") and key not in self._cancelled:
            self._requeue(key)
        elif state == "done":
            self._requeued.pop(key, None)

    def _consume(self, item: _Item, st: Any, profile: str, by_entry: dict[int, tuple[int, int]],
                 job: Any, total: int) -> tuple[int, str]:
        """Write the events of one pass. Returns (results dropped as worker failures, end state)."""
        key = (item.project, item.binary_id)
        last = time.monotonic()
        lost = 0
        while True:
            try:
                msg = self._events.get(timeout=EVENT_WAIT_S)
            except queue.Empty:
                if not self.ix.worker.running():
                    self._finish(key, "interrupted", "worker stopped during the pass")
                    return lost, "interrupted"
                if time.monotonic() - last > STALL_S:
                    try:
                        self.ix.worker.request("cancel_bulk", {"program": item.program}, timeout=30)
                    except WorkerError:
                        pass
                    self._finish(key, "error", f"no progress for {STALL_S:.0f}s")
                    return lost, "error"
                continue
            if msg.get("program") != item.program or msg.get("job") != job:
                continue
            last = time.monotonic()
            if msg["event"] == "decompile_results":
                lost += sum(1 for r in msg.get("results") or []
                            if r.get("status") != "ok" and is_transient_decomp_error(r.get("error")))
                self.write_results(st, profile, by_entry, msg)
                continue
            state = str(msg.get("state") or "running")
            p = BulkProgress(
                state, done=int(msg.get("done") or 0), total=int(msg.get("total") or total),
                rate=float(msg.get("rate") or 0.0), threads=int(msg.get("threads") or 0),
                processors=int(msg.get("processors") or 0), ok=int(msg.get("ok") or 0),
                failed=int(msg.get("failed") or 0), message=str(msg.get("message") or ""))
            self._progress[key] = p
            if state in TERMINAL:
                return lost, state

    def _finish(self, key: tuple[str, int], state: str, message: str) -> None:
        old = self._progress.get(key) or BulkProgress(state)
        self._progress[key] = BulkProgress(state, old.done, old.total, 0.0, old.threads,
                                           old.processors, old.ok, old.failed, message)

    @staticmethod
    def write_results(st: Any, profile: str, by_entry: dict[int, tuple[int, int]],
                      msg: dict[str, Any]) -> int:
        """Write one decompile_results event to the index. Returns the rows written."""
        cols = msg.get("ast_columns") or []
        items = []
        for r in msg.get("results") or []:
            hit = by_entry.get(int(r["entry"]))
            if hit is None:
                continue
            fid, version = hit
            ok = r.get("status") == "ok"
            err = None if ok else (r.get("error") or r.get("status"))
            if r.get("status") == "timeout":   # marks a short-timeout row: `function` retries once
                err = f"{BG_TIMEOUT}: {err}"
            items.append({
                "function_id": fid, "fn_version": version, "status": r.get("status") or "error",
                "c_text": r.get("c_text") if ok else None,
                "error": err,
                "ast": [dict(zip(cols, row)) for row in r.get("ast") or []] if ok else [],
            })
        return st.save_decomp_batch(profile, items, _now())
