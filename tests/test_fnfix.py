"""Missing functions at C++ entry points: candidates, the server round trip (fake worker), idempotence."""

from __future__ import annotations

import pytest

from airlock.server import cpp, fnfix
from airlock.worker.protocol import WorkerError
from test_tools import DATA, FakeWorker, fill, make_ctx

NEW_HANDLER = 0x401400
NEW_VSLOT = 0x401500
FAILING = 0x401600


class FixWorker(FakeWorker):
    """create_functions makes NEW_* functions; extract then lists them (and an edge from one)."""

    def __init__(self) -> None:
        super().__init__()
        self.created = False
        self.exit_on: set[int] = set()      # 1-based create_functions calls that end with the worker dying
        self.made: set[int] = set()

    def request(self, op, args=None, timeout=0):
        if op == "create_functions" and op != self.fail_op:
            self.calls.append((op, args))
            n = self.count("create_functions")
            if n in self.exit_on:
                raise WorkerError("worker_exited", "worker process exited")
            got = set(args["addresses"])
            made = got & {NEW_HANDLER, NEW_VSLOT}
            self.made |= made
            self.created = self.created or bool(made)
            return {"created": len(made), "skipped": 0, "failed": len(got - made),
                    "reasons": {"created": len(made), "failed": len(got - made)},
                    "sample": {"failed": [hex(a) for a in got - made]}}
        if op == "extract" and self.created and args["kind"] in ("functions", "edges"):
            self.calls.append((op, args))
            cols, rows = DATA[args["kind"]]
            if args["kind"] == "functions":
                rows = rows + [["ram", a, f"FUN_{a:08x}", "auto", "DEFAULT", None, "void f(void)",
                                "__cdecl", 8, 0, 0] for a in sorted(self.made)]
            else:
                rows = rows + [[0x401405, NEW_HANDLER, "ram", 0x401200, 0x401200, "call"]]
            return {"columns": cols, "rows": rows, "done": True, "next_offset": None,
                    "image_base": 0x400000, "pointer_size": 4}
        return super().request(op, args, timeout)


def _setup(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.worker = ctx.indexer.worker = FixWorker()
    ctx.worker.project_path = str(ctx.indexer.paths("proj", create=True).ghidra)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    with st.db:
        st.db.executemany(
            "INSERT INTO msgmap_entry(binary_id, class, map_addr, message, code, ctrl_id, last_id, sig, "
            "handler, seq) VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(bid, "CFoo", 0x403000, 0x111, 0, 1, 1, 1, 0x401100, 0),       # already a function
             (bid, "CFoo", 0x403000, 0x111, 0, 2, 2, 1, NEW_HANDLER, 1),    # missing
             (bid, "CFoo", 0x403000, 0x111, 0, 3, 3, 1, FAILING, 2)])       # creation fails
        st.db.executemany(
            "INSERT INTO vtable_slot(binary_id, vtable_addr, slot, target) VALUES (?,?,?,?)",
            [(bid, 0x404000, 0, 0x401000), (bid, 0x404000, 1, NEW_VSLOT), (bid, 0x404000, 2, NEW_HANDLER)])
        st.set_meta(cpp.meta_key(bid), str(cpp.CPP_VERSION))
    return ctx, st, bid


def test_candidates_are_missing_entries_only(tmp_path):
    ctx, st, bid = _setup(tmp_path)
    assert fnfix.candidates(st, bid) == sorted([NEW_HANDLER, NEW_VSLOT, FAILING])


def test_round_trip_creates_and_relinks_once(tmp_path):
    ctx, st, bid = _setup(tmp_path)
    b = st.get_binary_by_id(bid)
    ix, w = ctx.indexer, ctx.worker
    assert ix.create_missing_functions("proj", st, b) == 2
    sent = [a for o, a in w.calls if o == "create_functions"]
    assert len(sent) == 1 and sent[0]["addresses"] == sorted([NEW_HANDLER, NEW_VSLOT, FAILING])
    q = st.db.execute
    for a in (NEW_HANDLER, NEW_VSLOT):
        assert q("SELECT 1 FROM function WHERE binary_id=? AND entry=?", (bid, a)).fetchone()
    # the new function's edge is linked to its function id
    row = q("SELECT src_fn FROM edge WHERE binary_id=? AND src_addr=?", (bid, 0x401405)).fetchone()
    assert row is not None and row[0] is not None
    assert not fnfix.stale(st, bid)
    assert '"failed":1' in st.get_meta(fnfix.info_key(bid))
    # idempotent: no second worker call even though one address still has no function
    assert ix.create_missing_functions("proj", st, b) == 0
    assert len([1 for o, _ in w.calls if o == "create_functions"]) == 1


def test_old_version_runs_again(tmp_path):
    ctx, st, bid = _setup(tmp_path)
    b = st.get_binary_by_id(bid)
    ctx.indexer.create_missing_functions("proj", st, b)
    st.set_meta(fnfix.meta_key(bid), "0")
    assert fnfix.stale(st, bid)
    ctx.indexer.create_missing_functions("proj", st, b)       # runs, creates nothing new
    assert len([1 for o, _ in ctx.worker.calls if o == "create_functions"]) == 2
    assert not fnfix.stale(st, bid)


def test_skipped_without_cpp_tables_or_candidates(tmp_path):
    ctx, st, bid = _setup(tmp_path)
    b = st.get_binary_by_id(bid)
    st.set_meta(cpp.meta_key(bid), "0")                       # tables not derived yet
    assert ctx.indexer.create_missing_functions("proj", st, b) == 0
    assert ctx.worker.count("create_functions") == 0 and fnfix.stale(st, bid)
    st.set_meta(cpp.meta_key(bid), str(cpp.CPP_VERSION))
    with st.db:
        st.db.execute("DELETE FROM msgmap_entry")
        st.db.execute("DELETE FROM vtable_slot")
    assert ctx.indexer.create_missing_functions("proj", st, b) == 0
    assert ctx.worker.count("create_functions") == 0 and not fnfix.stale(st, bid)


def test_worker_failure_is_not_recorded(tmp_path):
    ctx, st, bid = _setup(tmp_path)
    ctx.worker.fail_op = "create_functions"
    b = st.get_binary_by_id(bid)
    with pytest.raises(WorkerError):
        ctx.indexer.create_missing_functions("proj", st, b)
    assert fnfix.stale(st, bid)                                # retried on the next open


def test_chunks_and_conventions_only_with_the_last(tmp_path, monkeypatch):
    ctx, st, bid = _setup(tmp_path)
    monkeypatch.setattr(fnfix, "BATCH", 1)
    got: list[tuple[int, int]] = []
    assert ctx.indexer.create_missing_functions("proj", st, st.get_binary_by_id(bid),
                                                progress=lambda d, n: got.append((d, n))) == 2
    assert got == [(0, 3), (1, 3), (2, 3), (3, 3)]
    sent = [a for o, a in ctx.worker.calls if o == "create_functions"]
    assert [a["addresses"] for a in sent] == [[NEW_HANDLER], [NEW_VSLOT], [FAILING]]
    assert [a["conventions"] for a in sent] == [False, False, True]


def test_worker_exit_is_recovered_once(tmp_path, monkeypatch):
    ctx, st, bid = _setup(tmp_path)
    monkeypatch.setattr(fnfix, "BATCH", 1)
    ctx.worker.exit_on = {2}                  # the worker dies on the second chunk, the first was saved
    assert ctx.indexer.create_missing_functions("proj", st, st.get_binary_by_id(bid)) == 2
    sent = [a["addresses"] for o, a in ctx.worker.calls if o == "create_functions"]
    assert sent == [[NEW_HANDLER], [NEW_VSLOT], [NEW_VSLOT], [FAILING]]   # the handler is not sent again
    assert ctx.worker.count("extract") >= 2                                # functions were re-read
    assert not fnfix.stale(st, bid)
    for a in (NEW_HANDLER, NEW_VSLOT):
        assert st.db.execute("SELECT 1 FROM function WHERE binary_id=? AND entry=?", (bid, a)).fetchone()
    log = (ctx.indexer.paths("proj").logs / "project.log").read_text(encoding="utf-8")
    assert "worker lost during create_functions (worker_exited" in log


def test_second_worker_exit_raises(tmp_path, monkeypatch):
    ctx, st, bid = _setup(tmp_path)
    monkeypatch.setattr(fnfix, "BATCH", 1)
    ctx.worker.exit_on = {2, 3}
    with pytest.raises(WorkerError) as ei:
        ctx.indexer.create_missing_functions("proj", st, st.get_binary_by_id(bid))
    assert ei.value.code == "worker_exited" and fnfix.stale(st, bid)


def test_shutdown_during_creation_is_not_an_error(tmp_path):
    ctx, st, bid = _setup(tmp_path)
    orig = ctx.worker.request

    def stopped(op, args=None, timeout=0):
        if op == "create_functions":
            raise WorkerError("worker_stopped", "worker was stopped (server shutdown)")
        return orig(op, args, timeout)

    ctx.worker.request = ctx.indexer.worker.request = stopped
    assert ctx.indexer.create_missing_functions("proj", st, st.get_binary_by_id(bid)) == 0
    assert fnfix.stale(st, bid)                               # not recorded: done again at the next open
    log = (ctx.indexer.paths("proj").logs / "project.log").read_text(encoding="utf-8")
    assert "interrupted by the server shutdown" in log
