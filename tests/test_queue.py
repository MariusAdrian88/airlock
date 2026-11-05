"""Analysis queue, resume, manifest updates, remaining estimate, program_add (fake worker)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from airlock.projects import hash_file, read_manifest, write_manifest
from airlock.server.scan import ScanOption, ScannedFile, ScanResult
from airlock.server.tools import admin
from airlock.server.tools import queue as qt
from test_projects import make_pe
from test_tools import FakeWorker
from test_tools import make_ctx

_MB = 1 << 20
LAST: list = [None]


class QueueWorker(FakeWorker):
    """Completes every analysis by itself after a short delay; open_project can be gated."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()
        self.gate.set()
        self.imported: list[str] = []
        self.links: list[dict] = []
        self.delay = 0.15
        self.overrides: dict[tuple[str, str], tuple[list, list]] = {}

    def request(self, op, args=None, timeout=0):
        if op == "open_project":
            assert self.gate.wait(10), "gate never opened"
        if op == "import_binary":
            self.imported.append(args["program_name"])
        if op == "link_externals":
            self.links.append(args)
            return {"linked": [], "skipped": []}
        if op == "extract" and (args["program"], args["kind"]) in self.overrides:
            self.calls.append((op, args))
            cols, rows = self.overrides[(args["program"], args["kind"])]
            return {"columns": cols, "rows": rows, "done": True, "next_offset": None,
                    "image_base": 0x400000, "pointer_size": 4}
        if op == "analyze":
            self.calls.append((op, args))
            program = args["program"]
            threading.Timer(self.delay, lambda: self.emit(program=program, state="done")).start()
            return {"state": "analysing", "started": True}
        return super().request(op, args, timeout)


def make_project(tmp_path, specs, state="queued"):
    """specs: [(rel_path, group, code_mb)] -> (ctx, entries); artifacts and manifest written."""
    ctx = make_ctx(tmp_path)
    LAST[0] = ctx
    ctx.worker = ctx.indexer.worker = QueueWorker()
    ctx.worker.project_path = str(ctx.indexer.paths("proj", create=True).ghidra)
    ctx.worker.on_event(ctx.indexer._on_event)
    pp = ctx.indexer.paths("proj")
    src = tmp_path / "srcprog"
    src.mkdir(exist_ok=True)
    entries = []
    for i, (rel, group, mb) in enumerate(specs):
        f = make_pe(src / f"{i}_{Path(rel).name}")
        f.write_bytes(f.read_bytes() + bytes([i]) * (i + 1))  # distinct hashes
        sha = hash_file(f)
        (pp.artifacts / sha).write_bytes(f.read_bytes())
        entries.append({"path": rel, "group": group, "kind": "pe", "size": f.stat().st_size,
                        "code_size": int(mb * _MB), "sha256": sha, "state": state})
    man = read_manifest(pp.manifest)
    man.update({"source": {"path": str(src), "root_exe": specs[0][0]}, "files": entries})
    write_manifest(pp.manifest, man)
    return ctx, entries


def wait_for(cond, secs=60.0):   # a bound on a state change, not a duration under test
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return
        time.sleep(0.02)
    ctx = LAST[0]
    ix = ctx.indexer
    st = ix.store("proj")
    detail = {
        "manifest": states(ctx),
        "index": {b.name: ix.get_status(st, b.id) for b in st.list_binaries()},
        "jobs": {j.program: (j.extracting, j.reached.is_set(), j.finished.is_set())
                 for j in ix._jobs.values()},
        "queue": [j.program for j in ix._queue], "running": ix._running and ix._running.program,
        "calls": [c[0] for c in ctx.worker.calls][-12:],
    }
    raise AssertionError(f"timed out: {detail}")


def idle(ctx):
    """Every job finished (links done), not only 'ready' in the manifest."""
    wait_for(lambda: all(j.finished.is_set() for j in list(ctx.indexer._jobs.values())))


def states(ctx):
    return {f["path"]: f.get("state") for f in read_manifest(ctx.indexer.paths("proj").manifest)["files"]}


SPECS = [("zz/first.dll", "third_party", 1.0), ("a/other.dll", "third_party", 3.0),
         ("app.exe", "core", 2.0), ("plug/p.dll", "own_plugin", 5.0),
         ("small.dll", "third_party", 0.5), ("core2.dll", "core", 0.25)]


def test_priority_order_states_and_manifest(tmp_path):
    ctx, entries = make_project(tmp_path, SPECS)
    ix, w = ctx.indexer, ctx.worker
    w.gate.clear()  # the queue thread stops in open_project of the first job
    queued = ix.enqueue("proj", entries[:1])
    assert queued == ["zz/first.dll"]
    wait_for(lambda: states(ctx)["zz/first.dll"] == "importing")
    assert ix.enqueue("proj", entries) == [e["path"] for e in entries[1:]]  # first is live: skipped
    assert ix.enqueue("proj", entries) == []  # idempotent
    st = states(ctx)
    assert st["zz/first.dll"] == "importing"
    assert all(v == "queued" for k, v in st.items() if k != "zz/first.dll")

    q = ix.queue_status("proj")
    assert [r.name for r in q.rows] == ["first.dll", "core2.dll", "app.exe", "p.dll", "small.dll",
                                         "other.dll"]
    assert q.current.name == "first.dll" and q.current.state == "importing"
    total = sum(e["code_size"] for e in entries) / _MB
    assert q.s_per_mb == pytest.approx(170.0) and q.overhead_s == pytest.approx(6.0)
    # queued: 5 binaries; current (first.dll, 1 MB) is floored at 25% of its estimate
    queued_est = 5 * 6 + (total - 1.0) * 170
    cur_est = 6 + 170.0
    assert queued_est + 0.25 * cur_est <= q.remaining_s <= queued_est + cur_est

    out = admin.index_status(ctx)
    assert "queue: 1 importing, 5 queued | remaining ~" in out
    assert "current: first.dll importing" in out
    assert "waiting, position 1 of 5, est ~" in out

    w.gate.set()
    wait_for(lambda: all(v == "ready" for v in states(ctx).values()))
    assert w.imported == ["first_dll", "core2_dll", "app_exe", "p_dll", "small_dll", "other_dll"]
    man = read_manifest(ix.paths("proj").manifest)
    for f in man["files"]:
        assert f["state"] == "ready" and "error" not in f
        assert f["analysis_s"] >= 0.1 and f["code_size"] > 0 and f["extract_s"] >= 0
    assert man["queue"]["s_per_mb"] > 0
    store = ix.store("proj")
    assert {ix.get_status(store, b.id)[0] for b in store.list_binaries()} == {"ready"}
    done = admin.index_status(ctx)
    assert "queue:" not in done and "analysed in" in done and done.count(" ready:") == 6


def test_model_priors_and_blend():
    from airlock.server import estimate as est
    assert est.refine([], 6, 170) == (6, 170)
    # one tiny binary: the fixed cost rises towards what was measured, the rate barely moves
    oh, rate = est.refine([(0.01, 30.0)], 6, 170)
    assert 6 < oh < 30 and rate == pytest.approx(170.0, rel=0.1)
    # a big binary: the rate rises, but only part of the way (blend with the prior)
    oh, rate = est.refine([(2.0, 480.0)], 6, 170)
    assert 170 < rate < (480 - oh) / 2.0 and oh < 12


def test_model_stable_and_monotonic():
    from airlock.server import estimate as est
    # real behaviour 8 s + 200 s/MB; the first (biggest) binary alone must not overshoot
    truth = lambda w: 8 + 200 * w   # noqa: E731
    seq = [2.0, 0.05, 0.1, 0.12, 0.2, 0.7]
    samples, rates = [], []
    for w in seq:
        samples.append((w, truth(w)))
        oh, rate = est.refine(samples, 6, 170)
        rates.append(rate)
        assert 0.4 * 170 <= rate <= 2.5 * 170 and 0 < oh <= 4 * 6
        # predictions grow with the work
        assert est.binary_seconds(1.0, oh, rate) < est.binary_seconds(1.5, oh, rate)
    assert all(abs(r - 200) < 35 for r in rates)        # never far from the truth
    assert abs(rates[0] - rates[-1]) < 20               # one binary does not swing the model
    # absurd samples are bounded
    oh, rate = est.refine([(0.001, 5000.0), (0.002, 9000.0)], 6, 170)
    assert oh <= 24 and rate <= 2.5 * 170
    oh, rate = est.refine([(3.0, 0.5)], 6, 170)
    assert rate >= 0.4 * 170


def test_work_mb_uses_function_estimate():
    from airlock.server import estimate as est
    assert est.work_mb(2 * 1024 * 1024) == pytest.approx(2.0)
    assert est.work_mb(2 * 1024 * 1024, 0) == pytest.approx(2.0)
    assert est.work_mb(1024 * 1024, 18000) == pytest.approx(18000 / est.FUNCS_PER_MB)
    # a function-dense binary of the same size gets a longer estimate
    assert est.work_mb(1 << 20, 12000) > est.work_mb(1 << 20, 6000)


def test_remaining_estimate_uses_measured_rate(tmp_path):
    ctx, entries = make_project(tmp_path, [("a.dll", "core", 1.0), ("b.dll", "core", 2.0),
                                           ("c.dll", "core", 4.0)])
    ix = ctx.indexer
    assert ix.s_per_mb([]) == pytest.approx(170.0)
    ctx.worker.gate.clear()
    ix.enqueue("proj", entries[:1])
    wait_for(lambda: states(ctx)["a.dll"] == "importing")
    ix.enqueue("proj", entries[1:])
    # as if measured: 1 MB took 520 s in total
    ix._mf_update("proj", entries[0]["sha256"], total_s=520.0)
    q = ix.queue_status("proj")
    oh, rate = ix.model(read_manifest(ix.paths("proj").manifest)["files"])
    assert rate > 170.0 and q.s_per_mb == pytest.approx(rate) and q.overhead_s == pytest.approx(oh)
    cur_est = oh + rate * 1
    assert 2 * oh + rate * 6 + 0.75 * cur_est <= q.remaining_s <= 2 * oh + rate * 6 + cur_est
    ctx.worker.gate.set()
    wait_for(lambda: all(v == "ready" for v in states(ctx).values()))


def test_running_binary_never_shows_zero_and_overrun(tmp_path):
    ctx, entries = make_project(tmp_path, [("a.dll", "core", 0.1), ("b.dll", "core", 0.1)])
    ix = ctx.indexer
    ctx.worker.gate.clear()
    ix.enqueue("proj", entries)
    wait_for(lambda: states(ctx)["a.dll"] == "importing")
    ix._running.started -= 1000.0     # far past the estimate (~32 s)
    q = ix.queue_status("proj")
    est_a = 6 + 0.1 * 170
    assert q.over_s == pytest.approx(1000.0 - est_a, abs=5)
    assert q.remaining_s >= 0.25 * est_a + est_a - 0.1   # a.dll floor + b.dll
    out = admin.index_status(ctx)
    assert "over estimate" in out and "s/binary" in out
    ctx.worker.gate.set()
    wait_for(lambda: all(v == "ready" for v in states(ctx).values()))


def test_error_state_and_queue_continues(tmp_path):
    ctx, entries = make_project(tmp_path, [("bad.dll", "core", 1.0), ("good.dll", "core", 2.0)])
    ix = ctx.indexer
    ctx.worker.fail_op = "import_binary"
    ix.enqueue("proj", entries[:1])
    wait_for(lambda: states(ctx)["bad.dll"] == "error")
    man = read_manifest(ix.paths("proj").manifest)
    assert "boom" in man["files"][0]["error"]
    ctx.worker.fail_op = None
    ix.enqueue("proj", entries[1:])
    wait_for(lambda: states(ctx)["good.dll"] == "ready")
    out = admin.index_status(ctx)
    assert "bad.dll error:" in out and "boom" in out


def test_resume_after_restart(tmp_path):
    ctx, entries = make_project(tmp_path, [("r.dll", "core", 1.0), ("q.dll", "core", 1.0),
                                           ("done.dll", "core", 1.0), ("err.dll", "core", 1.0),
                                           ("act.dll", "core", 1.0)])
    man = read_manifest(ctx.indexer.paths("proj").manifest)
    for f, s in zip(man["files"], ["analysing", "queued", "ready", "error", "extracting"]):
        f["state"] = s
    write_manifest(ctx.indexer.paths("proj").manifest, man)
    # a binary opened with open_binary (no manifest entry) that the server left mid-way
    pp = ctx.indexer.paths("proj")
    f = make_pe(tmp_path / "solo.exe")
    f.write_bytes(f.read_bytes() + b"solo")
    sha = hash_file(f)
    (pp.artifacts / sha).write_bytes(f.read_bytes())
    st = ctx.indexer.store("proj")
    bid = st.upsert_binary(sha, "solo.exe")
    ctx.indexer.set_status(st, bid, "analysing")

    assert ctx.indexer.resume_project("proj") == 4  # r, q, act + solo
    assert ctx.indexer.resume_project("proj") == 0  # once per process
    wait_for(lambda: states(ctx)["r.dll"] == "ready" and states(ctx)["act.dll"] == "ready"
             and states(ctx)["q.dll"] == "ready")
    wait_for(lambda: ctx.indexer.get_status(st, bid)[0] == "ready")
    s = states(ctx)
    assert s["done.dll"] == "ready" and s["err.dll"] == "error"  # untouched
    assert sorted(ctx.worker.imported) == ["act_dll", "q_dll", "r_dll", "solo_exe"]


def test_resume_via_resolve_project(tmp_path):
    ctx, entries = make_project(tmp_path, [("x.dll", "core", 1.0)])
    ctx.indexer.current = "proj"
    assert ctx.indexer.resolve_project() == "proj"  # first use of the project queues the work
    wait_for(lambda: states(ctx)["x.dll"] == "ready")


def test_same_file_name_gets_distinct_program_names(tmp_path):
    ctx, entries = make_project(tmp_path, [("a/util.dll", "core", 1.0), ("b/util.dll", "core", 1.0)])
    ctx.indexer.enqueue("proj", entries)
    wait_for(lambda: all(v == "ready" for v in states(ctx).values()))
    names = sorted(ctx.worker.imported)
    assert names[0] == "util_dll" and names[1].startswith("util_dll_") and len(set(names)) == 2


def test_status_caps_lines(tmp_path):
    specs = [(f"f{i}.dll", "third_party", 0.1) for i in range(20)]
    ctx, entries = make_project(tmp_path, specs)
    ctx.indexer.ready_hooks.clear()   # the map rebuild after each binary is not under test here
    ctx.worker.gate.clear()
    ctx.worker.delay = 0.01
    ctx.indexer.enqueue("proj", entries)
    out = admin.index_status(ctx)
    assert "20 binaries" in out and "  +4 more" in out
    assert len([ln for ln in out.splitlines() if ln.startswith("  #")]) == admin.STATUS_LINES
    ctx.worker.gate.set()
    wait_for(lambda: all(v == "ready" for v in states(ctx).values()), secs=180.0)


def _xbin_data(w):
    from test_tools import EDGE_COLS, FN_COLS, IMP_COLS
    exp = ["name", "ordinal", "space", "address"]
    fn = ["ram", 0x1000, "Foo", "auto", "DEFAULT", None, "void Foo(void)", "__stdcall", 0x20, 0, 0]
    w.overrides[("lib_dll", "functions")] = (FN_COLS, [fn])
    w.overrides[("lib_dll", "exports")] = (exp, [["Foo", None, "ram", 0x1010]])  # inside Foo
    for k in ("imports", "strings", "edges"):
        w.overrides[("lib_dll", k)] = ({"imports": IMP_COLS, "strings": ["space", "address", "encoding",
                                       "length", "value"], "edges": EDGE_COLS}[k], [])
    main = ["ram", 0x401000, "main", "user", "USER_DEFINED", None, "int main(void)", "__cdecl", 0x40, 0, 0]
    thunk = ["ram", 0x401300, "Foo", "library", "IMPORTED", None, "void Foo(void)", "__stdcall", 6, 1, 0]
    w.overrides[("app_exe", "functions")] = (FN_COLS, [main, thunk])
    w.overrides[("app_exe", "imports")] = (IMP_COLS, [["LIB.DLL", "Foo", None, "ram", 0x402000]])
    w.overrides[("app_exe", "exports")] = (exp, [])
    w.overrides[("app_exe", "strings")] = (["space", "address", "encoding", "length", "value"], [])
    w.overrides[("app_exe", "edges")] = (EDGE_COLS, [])


def _xedges(ctx, src_name):
    st = ctx.indexer.store("proj")
    b = st.get_binary(src_name)
    return {(x.src_addr, x.dst_entry) for x in st.cross_from_binary(b.id)}


def test_cross_links_dll_first(tmp_path):
    ctx, entries = make_project(tmp_path, [("lib.dll", "core", 1.0), ("app.exe", "core", 1.0)])
    w = ctx.worker
    _xbin_data(w)
    ctx.indexer.enqueue("proj", entries[:1])
    wait_for(lambda: states(ctx)["lib.dll"] == "ready")
    ctx.indexer.enqueue("proj", entries[1:])
    wait_for(lambda: states(ctx)["app.exe"] == "ready")
    idle(ctx)
    # before analysing app.exe its LIB.DLL external is pointed at the program already there
    assert w.links[0] == {"links": [{"program": "app_exe", "libs": {"lib.dll": "lib_dll"}}]}
    assert _xedges(ctx, "app.exe") == {(0x402000, 0x1000), (0x401300, 0x1000)}
    st = ctx.indexer.store("proj")
    foo = st.function_at(st.get_binary("lib.dll").id, 0x1000)
    assert {x.src_addr for x in st.cross_to_function(foo)} == {0x402000, 0x401300}
    assert "links out 2 in 0" in admin.index_status(ctx)


def test_cross_links_exe_first_updates_earlier_program(tmp_path):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0), ("lib.dll", "core", 1.0)])
    w = ctx.worker
    _xbin_data(w)
    ctx.indexer.enqueue("proj", entries[:1])
    wait_for(lambda: states(ctx)["app.exe"] == "ready")
    idle(ctx)
    assert w.links == []  # nothing to link to yet
    assert _xedges(ctx, "app.exe") == set()
    ctx.indexer.enqueue("proj", entries[1:])
    wait_for(lambda: states(ctx)["lib.dll"] == "ready")
    idle(ctx)
    # when lib.dll arrives, the earlier app.exe gets its external path and its index edges
    assert {"links": [{"program": "app_exe", "libs": {"lib.dll": "lib_dll"}}]} in w.links
    assert _xedges(ctx, "app.exe") == {(0x402000, 0x1000), (0x401300, 0x1000)}


# -- program_add ---------------------------------------------------------------------

def _sf(rel, group, code=1 << 20, dll=True):
    return ScannedFile(rel, "pe", group, 2 << 20, code, 32, dll, False, False, None, None, (), 0)


@pytest.fixture
def scanned(tmp_path, monkeypatch):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0)], state="ready")
    src = Path(read_manifest(ctx.indexer.paths("proj").manifest)["source"]["path"])
    (src / "plug").mkdir(exist_ok=True)
    for rel, i in (("plug/p1.dll", 7), ("plug/p2.dll", 8), ("third.dll", 9)):
        f = make_pe(src / rel)
        f.write_bytes(f.read_bytes() + bytes([i]) * i)
    (src / "data.bin").write_bytes(b"x")
    app = _sf("app.exe", "core", dll=False)
    p1, p2 = _sf("plug/p1.dll", "own_plugin", 2 << 20), _sf("plug/p2.dll", "own_plugin", 1 << 20)
    third = _sf("third.dll", "third_party", 4 << 20)
    data = ScannedFile("data.bin", "data", "data", 1, 0, None, False, False, False, None, None, (), 0)
    opts = (ScanOption("A", "Core", ("core",), (app,), 1 << 20, 80.0),
            ScanOption("B", "Core + own plugins", ("core", "own_plugin"), (app, p1, p2), 4 << 20, 320.0),
            ScanOption("C", "+ third party", ("core", "own_plugin", "third_party"),
                       (app, p1, p2, third), 8 << 20, 640.0))
    res = ScanResult(src, "app.exe", "x", (app, p1, p2, third, data), (), (), opts, "B")
    seen = []
    monkeypatch.setattr(qt, "scan_program", lambda path, root_exe=None, s_per_code_mb=120.0, overhead_s=20.0:
                        seen.append((path, root_exe)) or res)
    ctx.indexer.current = "proj"
    ctx.worker.gate.clear()  # keep the queue parked so the states stay "queued"
    ctx.seen = seen
    return ctx


def test_program_add_option_then_nothing_new(scanned):
    ctx = scanned
    ix = ctx.indexer
    out = qt.program_add(ctx, "")  # no arguments: what could be added
    assert out.startswith("files not yet in the project per option: B +2, C +3")
    out = qt.program_add(ctx, "b")
    assert out.startswith("queued 2 files, 3.0 MB code, ~") and "p1.dll" in out and "p2.dll" in out
    assert ctx.seen[0][1] == "app.exe"
    man = read_manifest(ix.paths("proj").manifest)
    assert [f["path"] for f in man["files"]] == ["app.exe", "plug/p1.dll", "plug/p2.dll"]
    new = man["files"][1]
    assert new["group"] == "own_plugin" and new["state"] in ("queued", "importing")
    assert new["code_size"] == 2 << 20 and (ix.paths("proj").artifacts / new["sha256"]).is_file()
    assert qt.program_add(ctx, "B").startswith("nothing to add")
    out = qt.program_add(ctx, "C")  # only third.dll is new
    assert out.startswith("queued 1 files, 4.0 MB code")
    assert qt.program_add(ctx, "").startswith("nothing to add")
    ctx.worker.gate.set()
    wait_for(lambda: all(v == "ready" for v in states(ctx).values()) and len(states(ctx)) == 4)
    # app.exe was never enqueued by the test, only the added three went through the worker
    assert sorted(ctx.worker.imported) == ["p1_dll", "p2_dll", "third_dll"]


def test_program_add_files_and_errors(scanned):
    ctx = scanned
    assert qt.program_add(ctx, "Z").startswith("error bad_option:")
    assert qt.program_add(ctx, "", "nope.dll").startswith("error bad_file:")
    out = qt.program_add(ctx, "", "third.dll, P2.dll")  # by name, case-insensitive
    assert out.startswith("queued 2 files")
    out = qt.program_add(ctx, "", "data.bin")  # not a PE: nothing to queue
    assert out.startswith("nothing to add")
    ctx.worker.gate.set()
    wait_for(lambda: len(ctx.worker.imported) == 2)


# -- finishing: ready comes after the after-ready work ------------------------------------

def test_ready_follows_finishing_and_the_link_steps(tmp_path):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0), ("lib.dll", "core", 1.0)])
    ix, w = ctx.indexer, ctx.worker
    _xbin_data(w)
    history: list[tuple[str, str]] = []
    orig_state = ix._state

    def state(job, status, *a, **kw):
        history.append((job.program, status))
        return orig_state(job, status, *a, **kw)

    seen: dict[str, str] = {}

    def status_of(name):
        st = ix.store("proj")      # per thread: the hook runs on the extract thread
        return ix.get_status(st, st.get_binary(name).id)[0]

    orig_link = w.request

    def request(op, args=None, timeout=0):
        if op == "link_externals" and args["links"][0]["program"] == "app_exe":
            seen["at_link"] = status_of("lib.dll")      # lib.dll links the earlier app.exe: still finishing
        return orig_link(op, args, timeout)

    ix._state = state
    w.request = request
    ix.ready_hooks.append(lambda project, bid: seen.__setitem__(f"hook{bid}", ix.get_status(
        ix.store(project), bid)[0]))
    ix.enqueue("proj", entries[:1])
    wait_for(lambda: states(ctx)["app.exe"] == "ready")
    ix.enqueue("proj", entries[1:])
    wait_for(lambda: states(ctx)["lib.dll"] == "ready")
    idle(ctx)
    order = ["importing", "analysing", "extracting", "finishing", "ready"]
    for prog in ("app_exe", "lib_dll"):
        assert [s for p, s in history if p == prog] == order
    assert seen["at_link"] == "finishing"
    assert set(v for k, v in seen.items() if k.startswith("hook")) == {"finishing"}
    assert _xedges(ctx, "app.exe") == {(0x402000, 0x1000), (0x401300, 0x1000)}


def test_index_status_shows_finishing_step_and_tools_work(tmp_path):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0)])
    ix = ctx.indexer
    reached, release = threading.Event(), threading.Event()

    def slow_fix(project, store, b, progress=None):
        progress(1200, 3769)
        reached.set()
        assert release.wait(10)
        return 0

    ix.create_missing_functions = slow_fix
    ix.enqueue("proj", entries)
    assert reached.wait(20)
    try:
        assert states(ctx)["app.exe"] == "finishing"
        out = admin.index_status(ctx)
        assert "app.exe finishing: functions 1200/3769" in out
        assert "1 finishing" in out and " ready:" not in out
        assert ix.not_ready_error("proj", ix.store("proj"), ix.store("proj").get_binary("app.exe")) is None
        assert " finishing " in ctx_call_list(ctx)       # list_binaries shows the status
    finally:
        release.set()
    wait_for(lambda: states(ctx)["app.exe"] == "ready")
    idle(ctx)
    assert " ready:" in admin.index_status(ctx) and "finishing" not in admin.index_status(ctx)


def ctx_call_list(ctx):
    from airlock.server.tools import core
    return core.list_binaries(ctx)


def test_interrupted_finishing_is_completed_on_resume(tmp_path):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0)], state="finishing")
    ix = ctx.indexer
    st = ix.store("proj")
    bid = st.upsert_binary(entries[0]["sha256"], "app.exe")
    st.set_meta(f"program:{bid}", "app_exe")
    ix.set_status(st, bid, "finishing")
    assert ix.resume_project("proj") == 0
    assert ix.get_status(st, bid)[0] == "ready"
    assert states(ctx)["app.exe"] == "ready"
