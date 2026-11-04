"""Server side of the background decompile pass: config keys, store helpers, ordering,
scheduling after the analysis queue, writes to the index, cancel, index_status (fake worker)."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from airlock.config.loader import ConfigError, default_config_text, deep_merge, parse_jsonc, resolve
from airlock.server import bulk as bulkm
from airlock.server.bulk import BulkScheduler, order_candidates
from airlock.server.tools import admin, core
from test_projects import make_pe
from test_tools import FakeWorker, fill, make_ctx

AST_COLS = ["kind", "start_off", "end_off", "address", "target", "text"]


def cfg(**defaults):
    merged = deep_merge(parse_jsonc(default_config_text()),
                        {"ghidra_dir": "x", "defaults": defaults})
    return resolve(merged, "dirty", None)


# ── config ───────────────────────────────────────────────────────────────────

def test_config_defaults_for_the_pass():
    d = cfg().defaults
    assert d["bulk_decompile"] == "background"
    assert (d["decompile_cpu_min"], d["decompile_cpu_max"]) == (0.5, 0.75)


@pytest.mark.parametrize("bad", [
    {"bulk_decompile": "eager"}, {"bulk_decompile": 1},
    {"decompile_cpu_min": 0}, {"decompile_cpu_min": -0.1}, {"decompile_cpu_max": 1.5},
    {"decompile_cpu_max": "half"}, {"decompile_cpu_min": True},
    {"decompile_cpu_min": 0.9, "decompile_cpu_max": 0.5},
])
def test_config_rejects_bad_pass_settings(bad):
    with pytest.raises(ConfigError):
        cfg(**bad)


def test_config_accepts_edges():
    assert cfg(decompile_cpu_min=1, decompile_cpu_max=1, bulk_decompile="lazy")
    assert cfg(decompile_cpu_min=0.25, decompile_cpu_max=0.25)


# ── ordering and store helpers ───────────────────────────────────────────────

def test_order_candidates_features_then_callers_then_address():
    rows = [{"id": 1, "entry": 30, "callers": 0}, {"id": 2, "entry": 20, "callers": 5},
            {"id": 3, "entry": 10, "callers": 5}, {"id": 4, "entry": 40, "callers": 1},
            {"id": 5, "entry": 50, "callers": 0}]
    assert [r["id"] for r in order_candidates(rows, set())] == [3, 2, 4, 1, 5]
    assert [r["id"] for r in order_candidates(rows, {5, 4})] == [4, 5, 3, 2, 1]


def test_candidates_skip_thunks_externals_and_valid_cache(tmp_path):
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    rows = st.decomp_candidates(bid, "prof1")
    assert sorted(r["entry"] for r in rows) == [0x401000, 0x401100, 0x401200]  # no thunk/external
    assert {r["entry"]: r["callers"] for r in rows} == {0x401000: 1, 0x401100: 1, 0x401200: 2}
    assert st.decomp_target_count(bid) == 3
    main = st.function_at(bid, 0x401000)
    st.upsert_decomp(main.id, main.version, "prof1", "ok", c_text="x")
    assert 0x401000 not in {r["entry"] for r in st.decomp_candidates(bid, "prof1")}
    assert st.decomp_current_count(bid, "prof1") == 1
    # another profile (re-analysed binary) makes the row stale: it is planned again
    assert 0x401000 in {r["entry"] for r in st.decomp_candidates(bid, "prof2")}
    assert st.decomp_current_count(bid, "prof2") == 0


def test_save_decomp_batch_writes_rows_and_skips_changed_versions(tmp_path):
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    a, b = st.function_at(bid, 0x401000), st.function_at(bid, 0x401100)
    ast = [{"kind": "call", "start_off": 1, "end_off": 5, "address": 9, "target": 0x401100,
            "text": "OnFoo"}]
    with st.db:
        st.db.execute("UPDATE function SET version=version+1 WHERE id=?", (b.id,))  # renamed
    n = st.save_decomp_batch("prof1", [
        {"function_id": a.id, "fn_version": a.version, "status": "ok", "c_text": "T", "ast": ast},
        {"function_id": b.id, "fn_version": b.version, "status": "ok", "c_text": "U", "ast": ast},
    ], "now")
    assert n == 1
    assert st.get_decomp(a, "prof1").c_text == "T" and len(st.get_ast_nodes(a.id)) == 1
    assert st.db.execute("SELECT COUNT(*) FROM decomp WHERE function_id=?", (b.id,)).fetchone()[0] == 0
    # a failed retry replaces the ast and records the status
    st.save_decomp_batch("prof1", [{"function_id": a.id, "fn_version": a.version,
                                    "status": "timeout", "error": "slow"}], "now")
    d = st.get_decomp(a, "prof1")
    assert d.status == "timeout" and d.c_text is None and st.get_ast_nodes(a.id) == []


# ── a fake worker that runs the pass ─────────────────────────────────────────

class BulkWorker(FakeWorker):
    def __init__(self) -> None:
        super().__init__()
        self.batch = 2
        self.run = threading.Event()
        self.run.set()                       # clear it to hold the pass between batches
        self.cancelled = False
        self.orders: list[list[int]] = []
        self.batches: list[int] = []
        self.timeouts: set[int] = set()
        self.on_batch: Any = None
        self.alive = True
        self.terminal = True
        self.thread: threading.Thread | None = None

    def running(self) -> bool:
        return self.alive

    def event(self, msg: dict[str, Any]) -> None:
        for cb in list(self.listeners):
            cb(msg)

    def request(self, op, args=None, timeout=0):
        args = args or {}
        if op == "bulk_decompile":
            self.calls.append((op, args))
            self.orders.append(list(args["order"]))
            self.thread = threading.Thread(target=self._pass, args=(args,), daemon=True)
            self.thread.start()
            return {"program": args["program"], "job": 7, "total": len(args["order"]),
                    "started": True, "threads": 3, "processors": 4}
        if op == "cancel_bulk":
            self.calls.append((op, args))
            self.cancelled = True
            return {"cancelling": True}
        return super().request(op, args, timeout)

    def _progress(self, program, state, done, total):
        self.event({"event": "decompile_progress", "program": program, "job": 7, "state": state,
                    "done": done, "total": total, "ok": done, "failed": 0, "rate": 12.5,
                    "threads": 3, "processors": 4})

    def _pass(self, args):
        program, order = args["program"], args["order"]
        done = 0
        for i in range(0, len(order), self.batch):
            self.run.wait(10)
            if self.cancelled:
                self._progress(program, "cancelled", done, len(order))
                return
            part = order[i:i + self.batch]
            results = []
            for e in part:
                if e in self.timeouts:
                    results.append({"entry": e, "status": "timeout", "error": "timeout", "s": 1.0})
                else:
                    text = f"void f_{e:x}(void)\n{{\n  g();\n}}\n"
                    results.append({"entry": e, "status": "ok", "c_text": text, "s": 0.01,
                                    "ast": [["call", 25, 26, e + 4, 0x401100, "g"]]})
            if self.on_batch:
                self.on_batch(i)
            self.batches.append(len(results))
            self.event({"event": "decompile_results", "program": program, "job": 7,
                        "ast_columns": AST_COLS, "results": results})
            done += len(part)
            self._progress(program, "running", done, len(order))
        if self.terminal:
            self._progress(program, "done", done, len(order))


@pytest.fixture
def pass_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(bulkm, "IDLE_POLL_S", 0.01)
    monkeypatch.setattr(bulkm, "EVENT_WAIT_S", 0.05)
    c = make_ctx(tmp_path)
    c.config.defaults["bulk_decompile"] = "background"
    c.worker = c.indexer.worker = BulkWorker()
    c.worker.project_path = str(c.indexer.paths("proj", create=True).ghidra)
    c.indexer.bulk = BulkScheduler(c.indexer)
    return c


def wait_for(cond, secs=10.0):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_pass_decompiles_all_functions_and_writes_the_index(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    assert ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    # one request, in call-graph order: most called first; thunk and external left out
    assert ctx.worker.orders == [[0x401200, 0x401000, 0x401100]]
    req = ctx.worker.calls[[c[0] for c in ctx.worker.calls].index("bulk_decompile")][1]
    assert req["program"] == "app_exe" and req["timeout"] == 60
    assert (req["cpu_min"], req["cpu_max"]) == (0.5, 0.75)
    for e in (0x401000, 0x401100, 0x401200):
        fn = st.function_at(bid, e)
        d = st.get_decomp(fn, "prof1")          # valid for fn_version and analysis_profile
        assert d is not None and d.status == "ok" and d.c_text.startswith("void f_")
        nodes = st.get_ast_nodes(fn.id)
        assert [(n["kind"], n["target"]) for n in nodes] == [("call", 0x401100)]
    assert st.decomp_current_count(bid, "prof1") == 3
    assert ctx.worker.batches == [2, 1]          # bounded events, written as they arrive
    p = ctx.indexer.bulk.progress("proj", bid)
    assert p.state == "done" and p.done == 3 and p.total == 3
    # the cache is what `function` serves: no decompile request goes to the worker
    out = core.function(ctx, "0x401000")
    assert "void f_401000" in out and ctx.worker.count("decompile") == 0


def test_feature_entry_points_come_first(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    with st.db:
        st.db.execute("INSERT INTO feature(key, title) VALUES ('file-io', 'File I/O')")
        st.db.execute("INSERT INTO feature_entry(feature_key, binary_id, space, entry, reason) "
                      "VALUES ('file-io', ?, 'ram', ?, 'calls CreateFileW')", (bid, 0x401100))
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    assert ctx.worker.orders == [[0x401100, 0x401200, 0x401000]]


def test_feature_table_missing_falls_back(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    with st.db:
        st.db.execute("DROP TABLE feature_entry")
    assert st.feature_entry_function_ids(bid) == set()
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    assert ctx.worker.orders == [[0x401200, 0x401000, 0x401100]]


def test_cached_functions_are_not_planned_again(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    main = st.function_at(bid, 0x401000)
    st.upsert_decomp(main.id, main.version, "prof1", "ok", c_text="cached")
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    assert ctx.worker.orders == [[0x401200, 0x401100]]
    assert st.get_decomp(main, "prof1").c_text == "cached"
    # nothing left to do: no worker request at all
    ctx.worker.orders.clear()
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    assert ctx.worker.orders == []
    assert ctx.indexer.bulk.progress("proj", bid).state == "done"


def test_failures_are_recorded_as_status_rows(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ctx.worker.timeouts = {0x401100}
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    st = ctx.indexer.store("proj")
    fn = st.function_at(bid, 0x401100)
    d = st.get_decomp(fn, "prof1")
    assert d.status == "timeout" and d.error == "timeout" and d.c_text is None
    assert st.decomp_candidates(bid, "prof1") == []      # not retried by the pass


def test_changed_function_version_is_not_overwritten(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)

    def rename(_i):
        s = ctx.indexer.store("proj")
        with s.db:
            s.db.execute("UPDATE function SET version=version+1 WHERE entry=?", (0x401000,))
    ctx.worker.on_batch = rename
    ctx.worker.batch = 3
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    st = ctx.indexer.store("proj")
    assert st.decomp_current_count(bid, "prof1") == 2     # the renamed one is left for later
    assert 0x401000 in {r["entry"] for r in st.decomp_candidates(bid, "prof1")}


def test_pass_waits_for_the_analysis_queue(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ix = ctx.indexer
    idle = [False]
    ix.queue_idle = lambda: idle[0]
    ix.bulk.schedule("proj", bid)
    time.sleep(0.2)
    assert ctx.worker.count("bulk_decompile") == 0
    assert ix.bulk.progress("proj", bid).state == "waiting"
    line = admin.index_status(ctx)
    assert "background pass waiting for analysis" in line
    idle[0] = True
    assert ix.bulk.wait_idle()
    assert ctx.worker.count("bulk_decompile") == 1


def test_disabled_modes_and_runtime_group_do_nothing(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    assert not ctx.indexer.bulk.schedule("proj", bid, "runtime")
    ctx.config.defaults["bulk_decompile"] = "lazy"
    assert not ctx.indexer.bulk.schedule("proj", bid, "core")
    assert ctx.indexer.bulk.resume("proj") == 0
    assert ctx.indexer.bulk.wait_idle(1)
    assert ctx.worker.count("bulk_decompile") == 0


def test_cancel_stops_the_pass_and_keeps_partial_results(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ctx.worker.batch = 1
    ctx.worker.run.clear()
    ix = ctx.indexer
    ix.bulk.schedule("proj", bid)
    assert wait_for(lambda: ctx.worker.count("bulk_decompile") == 1)
    assert wait_for(lambda: ix.bulk.progress("proj", bid).state == "running")
    assert ix.bulk.cancel("proj", bid)
    ctx.worker.run.set()
    assert ix.bulk.wait_idle()
    assert ctx.worker.cancelled and ctx.worker.count("cancel_bulk") == 1
    assert ix.bulk.progress("proj", bid).state == "cancelled"
    st = ix.store("proj")
    assert st.decomp_current_count(bid, "prof1") < 3


def test_cancel_a_waiting_binary(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ix = ctx.indexer
    ix.queue_idle = lambda: False
    ix.bulk.schedule("proj", bid)
    time.sleep(0.05)
    assert ix.bulk.cancel("proj", bid)
    assert ix.bulk.wait_idle()
    assert ctx.worker.count("bulk_decompile") == 0
    assert ix.bulk.progress("proj", bid).state == "cancelled"


def test_worker_death_ends_the_pass_as_interrupted(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ctx.worker.terminal = False
    ctx.worker.batch = 3

    def die(_i):
        ctx.worker.alive = False
    ctx.worker.on_batch = die
    ctx.indexer.bulk.schedule("proj", bid)
    assert ctx.indexer.bulk.wait_idle()
    p = ctx.indexer.bulk.progress("proj", bid)
    assert p.state == "interrupted"
    assert "decompiled 3/3" in admin.index_status(ctx) or "interrupted" in admin.index_status(ctx)


def test_index_status_shows_progress_rate_and_threads(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ctx.worker.batch = 1
    ctx.worker.run.clear()
    ix = ctx.indexer
    ix.bulk.schedule("proj", bid)
    assert wait_for(lambda: ix.bulk.progress("proj", bid).state == "running")
    assert wait_for(lambda: ctx.worker.thread is not None)
    ctx.worker.run.set()                      # first batch goes through, then we look
    assert wait_for(lambda: ix.bulk.progress("proj", bid).done >= 1)
    out = admin.index_status(ctx)
    ix.bulk.wait_idle()
    final = admin.index_status(ctx)
    assert "decompiled 3/3" in final and "fn/s" not in final
    # a mid-pass line has the form: decompiled X/Y, R fn/s, threads N of P
    p = bulkm.BulkProgress("running", done=1, total=3, rate=12.5, threads=3, processors=4)
    ix.bulk._progress[("proj", bid)] = p
    st = ix.store("proj")
    with st.db:
        st.db.execute("DELETE FROM decomp")
    line = admin.index_status(ctx)
    assert "decompiled 0/3, 12.5 fn/s, threads 3 of 4" in line, (out, line)


def test_resume_schedules_ready_binaries_with_missing_functions(pass_ctx):
    ctx = pass_ctx
    bid = fill(ctx)
    ix = ctx.indexer
    assert ix.resume_project("proj") >= 0          # the resume hook runs the scheduler too
    assert ix.bulk.wait_idle()
    assert ctx.worker.orders == [[0x401200, 0x401000, 0x401100]]
    ctx.worker.orders.clear()
    assert ix.bulk.resume("proj") == 0             # all cached now
    assert ix.bulk.wait_idle() and ctx.worker.orders == []


def test_a_binary_that_becomes_ready_starts_the_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(bulkm, "IDLE_POLL_S", 0.01)
    ctx = make_ctx(tmp_path)
    ctx.config.defaults["bulk_decompile"] = "background"
    ctx.worker = ctx.indexer.worker = BulkWorker()
    ctx.worker.project_path = str(ctx.indexer.paths("proj", create=True).ghidra)
    ctx.worker.on_event(ctx.indexer._on_event)
    ctx.indexer.bulk = BulkScheduler(ctx.indexer)
    exe = make_pe(tmp_path / "App One.exe")
    core.open_binary(ctx, "proj", str(exe))
    ix = ctx.indexer
    st = ix.store("proj")
    b = st.list_binaries()[0]
    ctx.worker.emit(program="App_One_exe", state="done", pct=None)
    assert ix.job_for("proj", b.id).finished.wait(10)
    assert wait_for(lambda: ctx.worker.count("bulk_decompile") == 1)
    assert ix.bulk.wait_idle()
    assert ctx.worker.calls[-1][0] in ("bulk_decompile", "status", "open_project")
    assert st.decomp_current_count(b.id, "prof1") == 3
