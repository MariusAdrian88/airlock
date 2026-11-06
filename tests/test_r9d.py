"""Round 9 group D: strings regex/literal retry (P4), function creation reads back one function (P8),
search finds the program body of a Delphi/FPC program (P9). Synthetic stores."""

from __future__ import annotations

from airlock.server import cpp, targets as tg
from airlock.server.tools import core
from test_linking import _store
from test_r8g import _Info, _prog
from test_tools import make_ctx
from test_xbin_tools import _fn


def _strings_ctx(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    bid = st.upsert_binary("cd" * 32, "a.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="msvc", analysis_profile="p")
    st.insert_functions(bid, [_fn(0x401000, "main", 40)])
    st.insert_strings(bid, [(0x403000, "utf16le", "\\DiskInfo.ini"), (0x403100, "ascii", "C:\\Apps\\x")])
    ix.set_status(st, bid, "ready")
    return ctx


def test_strings_escaped_literal_retried_as_regex(tmp_path):
    ctx = _strings_ctx(tmp_path)
    out = core.strings(ctx, r"\.ini", with_refs=False).splitlines()
    assert out[0] == r"strings matching '\.ini': 1 (regex used: no literal match)"
    assert "DiskInfo.ini" in out[1]


def test_strings_regex_with_backslash_retried_as_literal(tmp_path):
    ctx = _strings_ctx(tmp_path)
    # as a regex `\A` is an anchor that never matches mid-pattern; as plain text it is a path
    out = core.strings(ctx, r"C:\Apps", regex=True, with_refs=False).splitlines()
    assert out[0].startswith(r"strings matching 'C:\Apps': 1") and "(literal used: no regex match)" in out[0]
    assert core.strings(ctx, "nothing here", regex=True).startswith("no strings match 'nothing here'")
    assert core.strings(ctx, "\\DiskInfo", with_refs=False).startswith("strings matching")   # literal first


def test_search_adds_program_body(tmp_path, monkeypatch):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "delphi")
    monkeypatch.setattr("airlock.projects.detect", lambda p: _Info(ent - base))
    out = core.search(ctx, "main").splitlines()
    assert out[0] == "search 'main': 1 hits"
    assert out[1] == f"function entry 0x{ent:08x} (program body: main)"
    st.rebuild_fts(bid)
    assert core.search(ctx, "Helper").splitlines()[1].startswith("function Helper")   # other queries unchanged


def test_search_main_real_function_has_no_body_line(tmp_path, monkeypatch):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "delphi")
    monkeypatch.setattr("airlock.projects.detect", lambda p: _Info(ent - base))
    st.insert_functions(bid, [_fn(base + 0x1800, "main", 40)])
    st.rebuild_fts(bid)
    out = core.search(ctx, "main")
    assert "program body" not in out and "function main" in out


class _W:
    def __init__(self, st, bid, addr, size=30, with_extract=True):
        self.calls, self.st, self.bid, self.addr, self.size, self.with_extract = [], st, bid, addr, size, with_extract

    def request(self, op, args, timeout=0):
        self.calls.append(op)
        if op == "create_functions":
            return {"created": 1, "conventions": {}}
        if op == "extract_at" and self.with_extract:
            a = self.addr
            return {"function_columns": ["space", "entry", "name", "name_state", "source", "namespace",
                                         "signature", "calling_conv", "size", "is_thunk", "is_external"],
                    "functions": [["ram", a, "FUN_x", "auto", "DEFAULT", None, "void FUN_x(void)", "unknown",
                                   self.size, 0, 0]],
                    "edge_columns": ["src_addr", "src_fn", "dst_space", "dst_addr", "dst_fn", "kind"],
                    "edges": [[a + 4, a, "ram", 0x401780, 0x401780, "call"]],
                    "ranges": [[a, a + self.size - 1]]}
        raise RuntimeError("no such op")


def _setup(tmp_path, monkeypatch, **kw):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "qt")
    addr = base + 0x1c00
    img = cpp.Image(4, base, [cpp.Section(base + 0x1000, b"\0" * 0x2000, True, 0x2000)])
    monkeypatch.setattr(cpp.Image, "from_pe", classmethod(lambda cls, p: img))
    ctx.worker = _W(st, bid, addr, **kw)
    ctx.indexer.worker = ctx.worker
    monkeypatch.setattr(ctx.indexer, "ensure_open", lambda p: None)
    return ctx, st, bid, base, addr


def test_create_on_demand_reads_only_the_new_function(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch)
    full = []
    monkeypatch.setattr(type(ctx.indexer), "reextract_code", lambda self, *a: full.append(a))
    st.insert_edges(bid, [(base + 0x1c10, base + 0x1780, "call"), (base + 0x1780 + 2, addr, "call")])
    st.link_edges(bid)                          # the incoming call to `addr` has dst_fn NULL
    t = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == addr
    assert ctx.worker.calls == ["create_functions", "extract_at"] and not full
    rows = st.db.execute("SELECT src_addr, dst_addr, src_fn, dst_fn FROM edge WHERE binary_id=? "
                         "AND kind='call' ORDER BY src_addr", (bid,)).fetchall()
    fid = t.fn.id
    helper = st.function_at(bid, base + 0x1780).id
    # the old edge starting in the new body was replaced; the incoming edge now ends in the new function
    assert [(r[0], r[1], r[2], r[3]) for r in rows] == [(base + 0x1780 + 2, addr, helper, fid),
                                                         (addr + 4, 0x401780, fid, helper)]


def test_create_on_demand_falls_back_to_full_read(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch, with_extract=False)
    full = []
    monkeypatch.setattr(type(ctx.indexer), "reextract_code",
                        lambda self, store, b, program: (full.append(1),
                                                         store.insert_functions(b.id, [_fn(addr, "FUN_x", 30)])))
    t = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and full == [1]


def test_replace_edges_in_matches_full_link(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    bid = st.upsert_binary("ef" * 32, "b.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="msvc", analysis_profile="p")
    st.insert_functions(bid, [_fn(0x401000, "A", 0x10), _fn(0x401100, "B", 0x10)])
    edges = [(0x401004, 0x401100, "call"), (0x401108, 0x401000, "call"), (0x401108, 0x401200, "call"),
             (0x401204, 0x401100, "call")]
    st.insert_edges(bid, edges[:3])
    st.link_edges(bid)
    st.insert_functions(bid, [_fn(0x401200, "C", 0x10)])
    st.replace_edges_in(bid, [(0x401200, 0x40120f)], [edges[3]])
    got = st.db.execute("SELECT src_addr,dst_addr,kind,src_fn,dst_fn FROM edge WHERE binary_id=? "
                        "ORDER BY 1,2,3", (bid,)).fetchall()
    st.link_edges(bid)
    want = st.db.execute("SELECT src_addr,dst_addr,kind,src_fn,dst_fn FROM edge WHERE binary_id=? "
                         "ORDER BY 1,2,3", (bid,)).fetchall()
    assert [tuple(r) for r in got] == [tuple(r) for r in want] and len(got) == 4
