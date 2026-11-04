"""Decompiler thread budget and the parallel work engine (no Ghidra imports, unit-testable).

Budget (DESIGN.md section 5 step 8)
- P = processors available to THIS process, read once at worker start:
  `os.process_cpu_count()` (respects affinity and job limits), else `os.cpu_count()`, else 1.
- N = max(1, floor(share * P)) with share = cpu_max while idle and cpu_min while Ghidra
  auto-analysis of another program runs or a foreground request is in progress.
- One of the N decompilers is reserved for foreground requests, so the background pass uses
  max(1, N - 1) threads. The foreground decompiler is created on demand and never waits for
  the background pass.
- Out-of-memory in a decompile lowers the cap on N for the rest of the process.

Engine: worker threads pull entries from one shared queue. Each thread owns a decompiler
(`make_ctx`). Before every entry a thread checks its index against the current allowed count,
so a changed N, or a cancel, applies between functions; a thread above the limit closes its
decompiler and parks. Results are handed out in batches (count and byte bounded), so protocol
messages stay small.
"""

from __future__ import annotations

import collections
import contextlib
import os
import sys
import threading
import time
from typing import Any, Callable, Iterator

DEFAULT_CPU_MIN = 0.5
DEFAULT_CPU_MAX = 0.75
BATCH_SIZE = 50          # results per batch (the "chunk" of DESIGN.md)
BATCH_BYTES = 512_000    # rough serialized size that also closes a batch
PROGRESS_INTERVAL_S = 1.0


def log(msg: str) -> None:
    print(f"[worker] {msg}", file=sys.stderr, flush=True)


def detect_processors() -> int:
    """Processors available to this process; never a fixed number."""
    fn = getattr(os, "process_cpu_count", None)  # Python 3.13+
    for getter in (fn, os.cpu_count):
        if getter is None:
            continue
        try:
            n = getter()
        except Exception:
            n = None
        if n and n > 0:
            return int(n)
    return 1


def threads_for(share: float, processors: int) -> int:
    """floor(share * processors), at least 1 (epsilon guards 0.75 * 4 style float noise)."""
    return max(1, int(share * processors + 1e-9))


def valid_share(x: Any, default: float) -> float:
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not (0 < x <= 1):
        return default
    return float(x)


class Pool:
    """Worker-wide decompiler budget. `analysis_running` says whether Ghidra auto-analysis runs."""

    def __init__(self, processors: int | None = None, cpu_min: float = DEFAULT_CPU_MIN,
                 cpu_max: float = DEFAULT_CPU_MAX,
                 analysis_running: Callable[[], bool] | None = None) -> None:
        self.processors = processors if processors is not None else detect_processors()
        self.analysis_running = analysis_running or (lambda: False)
        self._lock = threading.Lock()
        self._foreground = 0
        self._oom_cap: int | None = None
        self.cpu_min, self.cpu_max = DEFAULT_CPU_MIN, DEFAULT_CPU_MAX
        self.configure(cpu_min, cpu_max)

    def configure(self, cpu_min: Any, cpu_max: Any) -> None:
        lo = valid_share(cpu_min, DEFAULT_CPU_MIN)
        hi = valid_share(cpu_max, DEFAULT_CPU_MAX)
        if lo > hi:
            lo = hi
        self.cpu_min, self.cpu_max = lo, hi

    @property
    def n_min(self) -> int:
        return threads_for(self.cpu_min, self.processors)

    @property
    def n_max(self) -> int:
        return threads_for(self.cpu_max, self.processors)

    # -- foreground ---------------------------------------------------------

    @contextlib.contextmanager
    def foreground(self) -> Iterator[None]:
        with self._lock:
            self._foreground += 1
        try:
            yield
        finally:
            with self._lock:
                self._foreground -= 1

    @property
    def foreground_active(self) -> bool:
        return self._foreground > 0

    def busy(self) -> bool:
        return self._foreground > 0 or bool(self.analysis_running())

    # -- sizes --------------------------------------------------------------

    def total(self) -> int:
        """N: decompilers allowed right now (min share while busy, else max share), capped
        after an out-of-memory."""
        n = self.n_min if self.busy() else self.n_max
        cap = self._oom_cap
        if cap is not None:
            n = min(n, cap)
        return max(1, n)

    def background(self) -> int:
        """Threads for the background pass: N minus the reserved foreground decompiler."""
        return max(1, self.total() - 1)

    def max_background(self) -> int:
        n = self.n_max
        if self._oom_cap is not None:
            n = min(n, self._oom_cap)
        return max(1, n - 1)

    def on_oom(self) -> int:
        """Lower N by one for the rest of the process. Returns the new cap."""
        with self._lock:
            cur = self._oom_cap if self._oom_cap is not None else self.total()
            self._oom_cap = max(1, cur - 1)
            cap = self._oom_cap
        log(f"decompile ran out of memory: lowering decompiler threads to {cap}. "
            "Raise defaults.jvm_max_memory to allow more.")
        return cap

    def describe(self) -> dict[str, Any]:
        return {"processors": self.processors, "threads": self.total(),
                "background": self.background()}


class Engine:
    """Run `work(ctx, entry) -> result dict` over `entries` with the pool's thread budget.

    work() returns a dict with at least "entry" and "status" ("ok" | "timeout" | "error");
    status "cancelled" results are dropped, and {"oom": True} makes the engine lower N and
    retry the entry once. on_results(batch) receives lists of result dicts;
    on_progress(snapshot) is called about once a second, and once more at the end with
    state done | cancelled.
    """

    def __init__(self, entries: list[int], work: Callable[[Any, int], dict[str, Any]],
                 make_ctx: Callable[[], Any], close_ctx: Callable[[Any], None],
                 pool: Pool, on_results: Callable[[list[dict[str, Any]]], None],
                 on_progress: Callable[[dict[str, Any]], None] | None = None,
                 batch_size: int = BATCH_SIZE, batch_bytes: int = BATCH_BYTES,
                 progress_interval: float = PROGRESS_INTERVAL_S, park_poll: float = 0.1,
                 clock: Callable[[], float] = time.monotonic,
                 size_of: Callable[[dict[str, Any]], int] | None = None) -> None:
        self.entries = list(entries)
        self.work, self.make_ctx, self.close_ctx = work, make_ctx, close_ctx
        self.pool = pool
        self.on_results = on_results
        self.on_progress = on_progress
        self.batch_size, self.batch_bytes = max(1, batch_size), batch_bytes
        self.progress_interval, self.park_poll = progress_interval, park_poll
        self.clock = clock
        self.size_of = size_of or _result_size
        self._todo: collections.deque[tuple[int, int]] = collections.deque(
            (e, 0) for e in self.entries)
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._batch: list[dict[str, Any]] = []
        self._batch_bytes = 0
        self._flush_lock = threading.Lock()
        self.done = 0
        self.ok = 0
        self.failed = 0
        self.total = len(self.entries)
        self.peak_threads = 0
        self._active = 0
        self._started = 0.0
        self._samples: collections.deque[tuple[float, int]] = collections.deque(maxlen=16)
        self.state = "pending"

    # -- control ------------------------------------------------------------

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def snapshot(self, state: str | None = None) -> dict[str, Any]:
        now = self.clock()
        rate = 0.0
        if self._samples:
            t0, d0 = self._samples[0]
            if now - t0 >= 1.0:
                rate = (self.done - d0) / (now - t0)
        if rate <= 0 and self._started and now > self._started:
            rate = self.done / (now - self._started)
        return {"state": state or self.state, "done": self.done, "total": self.total,
                "ok": self.ok, "failed": self.failed, "rate": round(rate, 1),
                "threads": self.pool.total(), "active": self._active,
                "processors": self.pool.processors}

    # -- run ----------------------------------------------------------------

    def run(self) -> str:
        """Blocks until every entry is done or cancel() was called. Returns the final state."""
        self.state = "running"
        self._started = self.clock()
        self._samples.append((self._started, 0))
        n_threads = self.pool.max_background() if self.entries else 0
        threads = [threading.Thread(target=self._worker, args=(i,), daemon=True,
                                    name=f"airlock-decomp-{i}") for i in range(n_threads)]
        stop_progress = threading.Event()
        ticker = threading.Thread(target=self._tick, args=(stop_progress,), daemon=True,
                                  name="airlock-decomp-progress")
        ticker.start()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stop_progress.set()
        ticker.join(timeout=5)
        self._flush()
        self.state = "cancelled" if (self._cancel.is_set() and self.done < self.total) else "done"
        if self.on_progress:
            self.on_progress(self.snapshot())
        return self.state

    def _tick(self, stop: threading.Event) -> None:
        while not stop.wait(self.progress_interval):
            self._samples.append((self.clock(), self.done))
            if self.on_progress:
                try:
                    self.on_progress(self.snapshot())
                except Exception:
                    pass

    def _next(self) -> tuple[int, int] | None:
        with self._lock:
            return self._todo.popleft() if self._todo else None

    def _remaining(self) -> bool:
        with self._lock:
            return bool(self._todo)

    def _worker(self, index: int) -> None:
        ctx: Any = None
        try:
            while not self._cancel.is_set():
                if index >= self.pool.background():  # above the current N: park
                    if ctx is not None:
                        self._close(ctx)
                        ctx = None
                    if not self._remaining():
                        return
                    time.sleep(self.park_poll)
                    continue
                item = self._next()
                if item is None:
                    return
                entry, tries = item
                try:
                    if ctx is None:
                        ctx = self.make_ctx()
                    with self._lock:
                        self._active += 1
                        self.peak_threads = max(self.peak_threads, self._active)
                    try:
                        r = self.work(ctx, entry)
                    finally:
                        with self._lock:
                            self._active -= 1
                except Exception as e:  # a bad function must not stop the pass
                    r = {"entry": entry, "status": "error", "error": f"{type(e).__name__}: {e}"}
                if r.get("status") == "cancelled" or self._cancel.is_set() and r.get("status") != "ok":
                    continue
                if r.get("oom"):
                    self.pool.on_oom()
                    if ctx is not None:  # the failing decompiler is not trusted again
                        self._close(ctx)
                        ctx = None
                    if tries < 1:
                        with self._lock:
                            self._todo.appendleft((entry, tries + 1))
                        continue
                if r.get("status") != "ok" and ctx is not None and r.get("drop_ctx"):
                    self._close(ctx)  # e.g. after a timeout the native decompiler is replaced
                    ctx = None
                self._add(r)
        finally:
            if ctx is not None:
                self._close(ctx)

    def _close(self, ctx: Any) -> None:
        try:
            self.close_ctx(ctx)
        except Exception as e:
            log(f"closing a decompiler failed: {e}")

    def _add(self, r: dict[str, Any]) -> None:
        flush: list[dict[str, Any]] | None = None
        with self._lock:
            self.done += 1
            if r.get("status") == "ok":
                self.ok += 1
            else:
                self.failed += 1
            self._batch.append(r)
            self._batch_bytes += self.size_of(r)
            if len(self._batch) >= self.batch_size or self._batch_bytes >= self.batch_bytes:
                flush, self._batch, self._batch_bytes = self._batch, [], 0
        if flush:
            self._emit(flush)

    def _flush(self) -> None:
        with self._lock:
            flush, self._batch, self._batch_bytes = self._batch, [], 0
        if flush:
            self._emit(flush)

    def _emit(self, batch: list[dict[str, Any]]) -> None:
        with self._flush_lock:
            self.on_results(batch)


def _result_size(r: dict[str, Any]) -> int:
    return len(r.get("c_text") or "") + 60 * len(r.get("ast") or ()) + 100
