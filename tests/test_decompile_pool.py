"""Decompiler thread budget, the parallel Engine, the reader/writer lock and the worker's
request lanes. No Ghidra: the work function is a stub."""

from __future__ import annotations

import io
import os
import threading
import time
from typing import Any

import pytest

from airlock.worker import main as wm
from airlock.worker import pool as P
from airlock.worker.pool import Engine, Pool
from airlock.worker.protocol import decode, encode
from airlock.worker.rwlock import RWLock


# ── N computation ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("procs,n_min,n_max", [
    (1, 1, 1), (2, 1, 1), (3, 1, 2), (4, 2, 3), (8, 4, 6), (16, 8, 12), (64, 32, 48),
])
def test_thread_counts_follow_the_shares(procs, n_min, n_max):
    p = Pool(processors=procs)
    assert (p.n_min, p.n_max) == (n_min, n_max)
    assert P.threads_for(0.75, procs) == n_max
    assert n_min >= 1


def test_processor_detection_uses_affinity_limited_count(monkeypatch):
    monkeypatch.setattr(os, "process_cpu_count", lambda: 4, raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 64)
    assert P.detect_processors() == 4  # the process may use 4 of the machine's 64
    assert Pool().n_max == 3


def test_processor_detection_fallbacks(monkeypatch):
    monkeypatch.setattr(os, "process_cpu_count", lambda: None, raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 6)
    assert P.detect_processors() == 6
    monkeypatch.setattr(os, "cpu_count", lambda: None)
    assert P.detect_processors() == 1
    monkeypatch.delattr(os, "process_cpu_count", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    assert P.detect_processors() == 8


def test_shares_are_validated_and_ordered():
    p = Pool(processors=16, cpu_min=0.25, cpu_max=0.5)
    assert (p.n_min, p.n_max) == (4, 8)
    p.configure(0, 5)                    # out of range -> defaults
    assert (p.cpu_min, p.cpu_max) == (0.5, 0.75)
    p.configure(True, "x")
    assert (p.cpu_min, p.cpu_max) == (0.5, 0.75)
    p.configure(0.9, 0.6)                # min above max: clamped to max
    assert p.cpu_min == p.cpu_max == 0.6
    p.configure(None, None)
    assert (p.cpu_min, p.cpu_max) == (0.5, 0.75)


# ── share switching and the reserved foreground decompiler ─────────────────

def test_share_switches_with_analysis_and_foreground():
    analysing = [False]
    p = Pool(processors=16, analysis_running=lambda: analysing[0])
    assert p.total() == 12 and not p.busy()
    analysing[0] = True
    assert p.total() == 8 and p.busy()
    analysing[0] = False
    assert p.total() == 12
    with p.foreground():
        assert p.total() == 8 and p.foreground_active
        with p.foreground():
            assert p.total() == 8
        assert p.foreground_active
    assert p.total() == 12 and not p.foreground_active


@pytest.mark.parametrize("procs", [1, 2, 4, 16, 64])
def test_one_decompiler_is_reserved_for_the_foreground(procs):
    p = Pool(processors=procs)
    assert p.background() == max(1, p.total() - 1)
    assert p.background() >= 1
    assert p.max_background() == max(1, p.n_max - 1)
    if p.total() > 1:
        assert p.background() < p.total()


def test_oom_lowers_n_and_keeps_at_least_one(capsys):
    p = Pool(processors=16)
    assert p.total() == 12
    assert p.on_oom() == 11
    assert p.total() == 11 and p.max_background() == 10
    p.on_oom()
    assert p.total() == 10
    with p.foreground():                # the cap applies to the minimum share as well
        assert p.total() == 8
    for _ in range(30):
        p.on_oom()
    assert p.total() == 1 and p.background() == 1 and p.max_background() == 1
    assert "out of memory" in capsys.readouterr().err


# ── Engine ─────────────────────────────────────────────────────────────────

class Fake:
    """Stub work function that records order, concurrency and per-thread contexts."""

    def __init__(self, delay: float = 0.0, fail: set[int] | None = None) -> None:
        self.delay, self.fail = delay, fail or set()
        self.lock = threading.Lock()
        self.order: list[int] = []
        self.live = 0
        self.peak = 0
        self.live_log: list[tuple[int, int]] = []  # (done count at start, concurrent)
        self.ctxs: list[dict[str, Any]] = []
        self.closed: list[dict[str, Any]] = []

    def make_ctx(self) -> dict[str, Any]:
        c = {"id": len(self.ctxs), "closed": False}
        with self.lock:
            self.ctxs.append(c)
        return c

    def close_ctx(self, c: dict[str, Any]) -> None:
        c["closed"] = True
        with self.lock:
            self.closed.append(c)

    def work(self, ctx: dict[str, Any], entry: int) -> dict[str, Any]:
        assert not ctx["closed"]
        with self.lock:
            self.order.append(entry)
            self.live += 1
            self.peak = max(self.peak, self.live)
            self.live_log.append((len(self.order), self.live))
        try:
            if self.delay:
                time.sleep(self.delay)
        finally:
            with self.lock:
                self.live -= 1
        if entry in self.fail:
            return {"entry": entry, "status": "error", "error": "boom"}
        return {"entry": entry, "status": "ok", "c_text": f"f{entry}", "ast": []}


def engine(fake: Fake, entries: list[int], pool: Pool, batches: list | None = None,
           snaps: list | None = None, **kw: Any) -> Engine:
    return Engine(entries, fake.work, fake.make_ctx, fake.close_ctx, pool,
                  (batches if batches is not None else []).append,
                  snaps.append if snaps is not None else None, progress_interval=0.05,
                  park_poll=0.005, **kw)


def test_engine_keeps_the_given_order_with_one_thread():
    fake, batches = Fake(), []
    e = engine(fake, list(range(10, 0, -1)), Pool(processors=2), batches)
    assert e.pool.max_background() == 1
    assert e.run() == "done"
    assert fake.order == list(range(10, 0, -1))  # most wanted first
    assert [r["entry"] for b in batches for r in b] == fake.order
    assert (e.done, e.ok, e.failed, e.total) == (10, 10, 0, 10)


def test_engine_batches_are_bounded_and_complete():
    fake, batches = Fake(), []
    entries = list(range(123))
    e = engine(fake, entries, Pool(processors=2), batches, batch_size=50)
    e.run()
    assert [len(b) for b in batches] == [50, 50, 23]
    assert sorted(r["entry"] for b in batches for r in b) == entries


def test_engine_batches_also_close_on_bytes():
    fake, batches = Fake(), []
    e = engine(fake, list(range(10)), Pool(processors=2), batches, batch_size=50,
               batch_bytes=250, size_of=lambda r: 100)
    e.run()
    assert [len(b) for b in batches] == [3, 3, 3, 1]


def test_engine_failures_are_data_and_exceptions_do_not_stop_the_pass():
    fake, batches = Fake(fail={2}), []

    def work(ctx, entry):
        if entry == 3:
            raise RuntimeError("native crash")
        return fake.work(ctx, entry)

    e = Engine(list(range(5)), work, fake.make_ctx, fake.close_ctx, Pool(processors=2),
               batches.append)
    assert e.run() == "done"
    by = {r["entry"]: r for b in batches for r in b}
    assert by[2]["status"] == "error" and by[2]["error"] == "boom"
    assert by[3]["status"] == "error" and "native crash" in by[3]["error"]
    assert (e.ok, e.failed) == (3, 2)


def test_engine_uses_the_background_thread_count_and_one_context_per_thread():
    fake = Fake(delay=0.02)
    p = Pool(processors=8)                 # max 6 -> 5 background threads
    e = engine(fake, list(range(60)), p)
    e.run()
    assert 2 <= fake.peak <= 5
    assert len(fake.ctxs) <= 5
    assert all(c["closed"] for c in fake.ctxs)  # every decompiler is disposed at the end


def test_engine_applies_a_changed_n_between_functions():
    fake = Fake(delay=0.01)
    busy = [False]
    p = Pool(processors=16, analysis_running=lambda: busy[0])  # 11 background, 7 when busy
    e = engine(fake, list(range(400)), p)
    t = threading.Thread(target=e.run)
    t.start()
    while e.done < 100:
        time.sleep(0.005)
    busy[0] = True                         # an analysis starts: drop to the minimum share
    mark = len(fake.order)
    t.join(30)
    assert not t.is_alive()
    assert max(c for n, c in fake.live_log[:60]) >= 8       # used the idle maximum
    after = [c for n, c in fake.live_log if n > mark + 12]  # allow in-flight work to drain
    assert after and max(after) <= 7
    assert e.done == 400
    # parked threads gave their decompilers back
    assert all(c["closed"] for c in fake.ctxs)
    assert len(fake.closed) == len(fake.ctxs)


def test_engine_cancel_stops_between_functions_and_reports_cancelled():
    fake, batches, snaps = Fake(delay=0.01), [], []
    e = engine(fake, list(range(1000)), Pool(processors=8), batches, snaps)
    t = threading.Thread(target=e.run)
    t.start()
    while e.done < 20:
        time.sleep(0.005)
    e.cancel()
    t.join(10)
    assert not t.is_alive()
    assert e.state == "cancelled" and 20 <= e.done < 1000
    assert snaps[-1]["state"] == "cancelled"
    # partial results were still handed out
    assert sum(len(b) for b in batches) == e.done
    assert all(c["closed"] for c in fake.ctxs)


def test_engine_drops_cancelled_results_and_cancels_before_start():
    fake = Fake()
    e = Engine([1, 2, 3], lambda c, x: {"entry": x, "status": "cancelled"}, fake.make_ctx,
               fake.close_ctx, Pool(processors=2), lambda b: pytest.fail("no results expected"))
    assert e.run() == "done" and e.done == 0
    e2 = engine(Fake(), [1, 2, 3], Pool(processors=2))
    e2.cancel()
    assert e2.run() == "cancelled" and e2.done == 0


def test_engine_out_of_memory_lowers_n_and_retries_once(capsys):
    fake, batches = Fake(), []
    seen = {"n": 0}

    def work(ctx, entry):
        if entry == 5 and seen["n"] == 0:
            seen["n"] += 1
            return {"entry": 5, "status": "error", "error": "out_of_memory", "oom": True}
        return fake.work(ctx, entry)

    p = Pool(processors=16)
    e = Engine(list(range(10)), work, fake.make_ctx, fake.close_ctx, p, batches.append)
    e.run()
    assert p.total() == 11
    by = {r["entry"]: r for b in batches for r in b}
    assert by[5]["status"] == "ok" and e.done == 10      # retried once, then fine
    assert "lowering decompiler threads" in capsys.readouterr().err


def test_engine_progress_snapshots_report_rate_threads_and_processors():
    fake, snaps = Fake(delay=0.01), []
    p = Pool(processors=4)
    e = engine(fake, list(range(80)), p, snaps=snaps)
    e.run()
    last = snaps[-1]
    assert last["state"] == "done" and last["done"] == last["total"] == 80
    assert last["processors"] == 4 and last["threads"] == 3
    assert last["rate"] > 0
    assert any(s["state"] == "running" for s in snaps)


def test_engine_foreground_demand_does_not_stall_the_background_pass():
    fake = Fake(delay=0.005)
    p = Pool(processors=4)
    e = engine(fake, list(range(60)), p)
    t = threading.Thread(target=e.run)
    t.start()
    with p.foreground():                   # a foreground request is "in progress"
        assert p.total() == 2 and p.background() == 1
        time.sleep(0.05)
    t.join(10)
    assert e.done == 60


# ── reader/writer lock ─────────────────────────────────────────────────────

def test_rwlock_readers_share_and_writers_exclude():
    lock = RWLock()
    inside, peak, writer_saw = [0], [0], []
    mu = threading.Lock()
    gate = threading.Barrier(3)

    def reader():
        with lock.read():
            with mu:
                inside[0] += 1
                peak[0] = max(peak[0], inside[0])
            gate.wait(5)                 # three readers are inside together
            with mu:
                inside[0] -= 1

    ts = [threading.Thread(target=reader) for _ in range(3)]
    [t.start() for t in ts]
    [t.join(10) for t in ts]
    assert peak[0] == 3

    def writer():
        with lock:
            writer_saw.append(lock.readers)
            time.sleep(0.02)

    with lock.read():
        w = threading.Thread(target=writer)
        w.start()
        time.sleep(0.05)
        assert writer_saw == []          # blocked while a reader is inside
    w.join(5)
    assert writer_saw == [0]


def test_rwlock_waiting_writer_blocks_new_readers_and_is_reentrant():
    lock = RWLock()
    order: list[str] = []
    r1_in, release_r1 = threading.Event(), threading.Event()

    def r1():
        with lock.read():
            r1_in.set()
            release_r1.wait(5)
            order.append("r1")

    def w():
        with lock:
            order.append("w")

    def r2():
        with lock.read():
            order.append("r2")

    t1 = threading.Thread(target=r1)
    t1.start()
    r1_in.wait(5)
    tw = threading.Thread(target=w)
    tw.start()
    time.sleep(0.05)                      # the writer is now waiting
    t2 = threading.Thread(target=r2)
    t2.start()
    time.sleep(0.05)
    assert order == []                    # r2 queued behind the waiting writer
    release_r1.set()
    for t in (t1, tw, t2):
        t.join(5)
    assert order == ["r1", "w", "r2"]
    with lock:                            # re-entrant writer, may also read
        with lock:
            with lock.read():
                pass
    assert lock.readers == 0


# ── request lanes in the worker ────────────────────────────────────────────

def _lines(buf: io.BytesIO) -> list[dict]:
    return [decode(x) for x in buf.getvalue().splitlines()]


def test_concurrent_ops_answer_while_a_serial_op_runs(monkeypatch):
    buf = io.BytesIO()
    monkeypatch.setattr(wm.STATE, "out", buf)
    started, release = threading.Event(), threading.Event()
    monkeypatch.setitem(wm.OPS, "slow_serial", lambda a: (started.set(), release.wait(10),
                                                          {"slow": True})[2])
    monkeypatch.setitem(wm.OPS, "queued_serial", lambda a: {"second": True})
    monkeypatch.setitem(wm.OPS, "status", lambda a: {"st": 1})

    def feed():
        yield encode({"id": 1, "op": "slow_serial"})
        started.wait(5)
        yield encode({"id": 2, "op": "queued_serial"})   # serial: waits behind id 1
        yield encode({"id": 3, "op": "hello"})
        yield encode({"id": 4, "op": "status"})
        deadline = time.monotonic() + 5
        while len(_lines(buf)) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        release.set()
        deadline = time.monotonic() + 5
        while len(_lines(buf)) < 4 and time.monotonic() < deadline:
            time.sleep(0.01)
        yield encode({"id": 5, "op": "shutdown"})

    wm.serve(feed())
    got = _lines(buf)
    ids = [m["id"] for m in got]
    assert set(ids[:2]) == {3, 4}                      # answered before the slow op finished
    assert ids.index(1) < ids.index(2)                 # serial lane keeps arrival order
    assert ids[-1] == 5 and got[-1]["data"] == {"bye": True}
    assert next(m for m in got if m["id"] == 3)["data"]["processors"] == wm.STATE.processors \
        or wm.STATE.processors is None
    assert all(m["ok"] for m in got)


def test_every_decompile_related_op_that_must_stay_responsive_is_concurrent():
    import airlock.worker.ghidra_ops  # noqa: F401  registers the ops
    for name in ("hello", "status", "cancel_analysis", "cancel_bulk", "decompile",
                 "decompile_batch", "bulk_decompile"):
        assert name in wm.CONCURRENT_OPS and name in wm.OPS
    for name in ("extract", "analyze", "link_externals", "open_project", "close_project",
                 "import_binary", "save", "start_ghidra"):
        assert name not in wm.CONCURRENT_OPS and name in wm.OPS
