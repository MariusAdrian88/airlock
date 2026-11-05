"""Plugin-interface links (folder-scan plugins) and function-pointer (fnptr) edges: synthetic
stores, invented names."""

from __future__ import annotations

from airlock import projects as P
from airlock.index.store import CODE_EDGES, GRAPH_EDGES
from airlock.server import graph as G
from airlock.server import linking
from airlock.server.projectmap import relations_lines
from airlock.server.tools import core
from airlock.server.tools import graphtools as gt
from test_linking import _add, _store
from test_tools import make_ctx
from test_xbin_tools import _fn


# -- plugin-interface linking ---------------------------------------------------------------

def _host(ix, st, gpa_names=("PlugInit", "PlugNotify", "PlugConfig"), folder="C:\\app\\PlugIns\\*.DLL",
          imports=(), find=False):
    fns = [_fn(0x401000, "Scan", 0x80), _fn(0x401300, "LoadLibraryA", 6, True, "library"),
           _fn(0x401310, "GetProcAddress", 6, True, "library"), _fn(0x401200, "Resolve", 0x40),
           _fn(0x401320, "FindFirstFileA", 6, True, "library")]
    edges = [(0x401008, 0x401300, "call"), (0x40100c, 0x401200, "call"), (0x401210, 0x401310, "call")]
    strs = []
    if folder:
        strs.append((0x403000, "ascii", folder))
        edges.append((0x401004, 0x403000, "data"))
    if find:
        edges.append((0x401010, 0x401320, "call"))
    for i, nm in enumerate(gpa_names):
        a = 0x403100 + i * 0x20
        strs.append((a, "ascii", nm))
        edges.append((0x401220 + i * 4, a, "read"))
    return _add(ix, st, "host.exe", "aa", 0x400000, fns, edges, strs, list(imports))


def _plug(ix, st, name, sha, exports):
    fns = [_fn(0x10001000 + i * 0x100, e) for i, e in enumerate(exports)]
    return _add(ix, st, name, sha, 0x10000000, fns,
                exps=[(e, i + 1, 0x10001000 + i * 0x100) for i, e in enumerate(exports)])


def test_folder_scan_plugin_interface_links(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    m = _host(ix, st)
    p1 = _plug(ix, st, "alpha.dll", "bb", ["PlugInit", "PlugNotify", "Helper"])
    p2 = _plug(ix, st, "beta.dll", "cc", ["PlugConfig", "Other"])      # one name, folder scan: linked
    p3 = _plug(ix, st, "gamma.dll", "dd", ["Unrelated"])
    linking.link_dynamic_for(st, m, [p1, p2, p3])
    rows = st.db.execute("SELECT * FROM xedge WHERE kind='dynamic' ORDER BY dst_binary, dst_entry").fetchall()
    assert [(r["dst_binary"], r["src_addr"], r["dst_entry"]) for r in rows] == [
        (p1, 0x401200, 0x10001000), (p1, 0x401200, 0x10001100), (p2, 0x401200, 0x10001000)]
    assert rows[0]["evidence"] == "interface name PlugInit; loaded by folder scan"
    libs = st.db.execute("SELECT dst_binary, dst_entry FROM xedge WHERE kind='dynlib' "
                         "ORDER BY dst_binary").fetchall()
    assert [(r["dst_binary"], r["dst_entry"]) for r in libs] == [(p1, -1), (p2, -1)]
    lines = relations_lines(None, st, {})
    assert any(ln.startswith("host.exe -> alpha.dll: 2 interface names via GetProcAddress (folder scan")
               for ln in lines)
    cg = core.callgraph(ctx, "host.exe!Resolve")
    assert "→ [alpha.dll] PlugInit" in cg and "(dynamic)" in cg


def test_run_time_path_needs_two_interface_names(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    m = _host(ix, st, folder=None)
    one = _plug(ix, st, "one.dll", "bb", ["PlugInit", "X"])
    two = _plug(ix, st, "two.dll", "cc", ["PlugInit", "PlugNotify"])
    assert linking.link_dynamic_for(st, m, [one, two]) == 3          # two dynamic + dynlib, only for two.dll
    assert {r["dst_binary"] for r in st.db.execute("SELECT dst_binary FROM xedge")} == {two}
    ev = st.db.execute("SELECT evidence FROM xedge WHERE kind='dynamic'").fetchone()[0]
    assert ev == "interface name PlugInit; loaded by run-time path"


def test_findfirstfile_with_loadlibrary_counts_as_folder_scan(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    m = _host(ix, st, folder=None, find=True)
    one = _plug(ix, st, "one.dll", "bb", ["PlugInit"])
    assert linking.link_dynamic_for(st, m, [one]) == 2


def test_generic_api_names_are_not_interface_names(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    m = _host(ix, st, gpa_names=("CreateFileA", "ReadFile", "PlugInit"),
              imports=[("kernel32.dll", "ReadFile", None, 0x405000)])
    shim = _plug(ix, st, "shim.dll", "bb", ["CreateFileA", "ReadFile"])   # exports API-like names only
    assert linking.link_dynamic_for(st, m, [shim]) == 0
    only_one = _plug(ix, st, "real.dll", "cc", ["PlugInit", "CreateFileA"])
    assert linking.link_dynamic_for(st, m, [only_one]) == 2           # folder scan: PlugInit (1 name)
    names = {r["evidence"] for r in st.db.execute("SELECT evidence FROM xedge WHERE kind='dynamic'")}
    assert names == {"interface name PlugInit; loaded by folder scan"}


def test_no_interface_link_without_folder_or_enough_names(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    m = _host(ix, st, gpa_names=("PlugInit",), folder=None)
    p = _plug(ix, st, "alpha.dll", "bb", ["PlugInit"])
    assert linking.link_dynamic_for(st, m, [p]) == 0


# -- fnptr edges ------------------------------------------------------------------------------

def _app(ix, st, extra_fns=(), edges=(), sha="ee"):
    fns = [_fn(0x401000, "Main", 0x80), _fn(0x401100, "OnTimer", 0x40), _fn(0x401200, "WndProc", 0x40),
           _fn(0x401300, "Thunk", 6, True), _fn(0x401400, "Setup", 0x40), *extra_fns]
    return _add(ix, st, "app.exe", sha, 0x400000, fns, list(edges))


def test_fnptr_from_push_offset(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    b = _app(ix, st, edges=[(0x401010, 0x401100, "data"),            # push offset OnTimer
                            (0x401014, 0x401200, "write"),            # mov [x], offset WndProc
                            (0x401018, 0x401300, "data"),             # thunk: skipped
                            (0x401020, 0x401000, "data"),             # self reference: skipped
                            (0x401404, 0x401100, "call")])           # a plain call is not fnptr
    rows = st.db.execute("SELECT src_addr, dst_addr FROM edge WHERE kind='fnptr' ORDER BY dst_addr").fetchall()
    assert [(r[0], r[1]) for r in rows] == [(0x401010, 0x401100), (0x401014, 0x401200)]
    main = st.function_at(b, 0x401000)
    assert [f.name for f in st.ptr_callees(main)] == ["OnTimer", "WndProc"]
    assert [f.name for f in st.callees(main)] == []                   # not a call
    assert [f.name for f in st.ptr_callers(st.function_at(b, 0x401100))] == ["Main"]
    assert st.link_fnptr(b) == 2                                      # idempotent
    assert st.db.execute("SELECT COUNT(*) FROM edge WHERE kind='fnptr'").fetchone()[0] == 2


def test_fnptr_table_edges_and_threshold(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    fns = [_fn(0x401500 + i * 0x20, f"Handler{i}", 0x10) for i in range(5)]
    edges = [(0x405000 + 4 * i, 0x401500 + i * 0x20, "data") for i in range(4)]       # table of 4
    edges += [(0x406000, 0x401500, "data"), (0x406004, 0x401520, "data")]             # only 2: no table
    edges += [(0x401010, 0x405000, "data"),                          # Main loads the table start
              (0x401404, 0x406000, "data")]                          # Setup loads the short one
    b = _app(ix, st, fns, edges)
    got = {(r["src_addr"], r["dst_addr"]) for r in st.db.execute(
        "SELECT src_addr, dst_addr FROM edge WHERE kind='fnptr'")}
    assert got == {(0x401010, 0x401500 + i * 0x20) for i in range(4)}
    main = st.function_at(b, 0x401000)
    assert len(st.ptr_callees(main)) == 4


def test_fnptr_table_cap(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    n = 300
    fns = [_fn(0x410000 + i * 0x10, f"V{i}", 0x8) for i in range(n)]
    edges = [(0x420000 + 4 * i, 0x410000 + i * 0x10, "data") for i in range(n)]
    edges.append((0x401010, 0x420000, "data"))
    b = _app(ix, st, fns, edges)
    assert st.db.execute("SELECT COUNT(*) FROM edge WHERE kind='fnptr'").fetchone()[0] == 256
    assert len(st.ptr_callees(st.function_at(b, 0x401000), 1000)) == 256


def test_xrefs_call_excludes_fnptr_and_code_edges_unchanged(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    _app(ix, st, edges=[(0x401010, 0x401100, "data"), (0x401404, 0x401100, "call")])
    assert "fnptr" not in CODE_EDGES and GRAPH_EDGES == CODE_EDGES + ("fnptr",)
    out = core.xrefs(ctx, "OnTimer", kind="call").splitlines()
    assert out[0].endswith("1 call") and "fnptr" not in "\n".join(out)
    out = core.xrefs(ctx, "OnTimer", kind="fnptr").splitlines()
    assert out[0].endswith("1 fnptr") and "Main" in out[1]


def test_callgraph_marks_ptr_hops(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    _app(ix, st, edges=[(0x401010, 0x401100, "data"), (0x401014, 0x401200, "data"),
                        (0x401018, 0x401400, "call")])
    cg = core.callgraph(ctx, "Main")
    assert next(ln for ln in cg.splitlines() if "OnTimer" in ln).endswith("(ptr)")
    assert not next(ln for ln in cg.splitlines() if "Setup" in ln).endswith("(ptr)")
    up = core.callgraph(ctx, "OnTimer", direction="callers")
    assert next(ln for ln in up.splitlines() if "Main" in ln).endswith("(ptr)")
    off = core.callgraph(ctx, "Main", pointers=False)
    assert "OnTimer" not in off and "Setup" in off


def test_graph_and_path_use_fnptr(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    b = _app(ix, st, edges=[(0x401010, 0x401100, "data"), (0x401114, 0x401200, "call")])
    g = G.build_graph(st, [b])
    names = {(g.info[x][0], g.info[y][0]) for (x, y) in g.directed}
    assert names == {("Main", "OnTimer"), ("OnTimer", "WndProc")}
    assert {(g.info[x][0], g.info[y][0]) for (x, y) in g.ptr_only} == {("Main", "OnTimer")}
    pp = ctx.indexer.paths("proj", create=True)
    man = P.read_manifest(pp.manifest)
    man["files"] = [{"path": "app.exe", "group": "core", "sha256": "ee" * 32}]
    P.write_manifest(pp.manifest, man)
    st.set_meta("link_version", str(linking.LINK_VERSION))
    assert ctx.bind_session("dirty", pp) is None
    out = gt.path(ctx, "Main", "WndProc", k=1)
    ls = [x for x in out.splitlines() if x.startswith("→")]
    assert len(ls) == 3
    assert ls[1].endswith("(via pointer)") and "ref at 0x00401010" in ls[1]
    assert "(via pointer)" not in ls[2] and "call at" in ls[2]


# -- relink -----------------------------------------------------------------------------------

def test_relink_upgrades_old_project(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    b = _app(ix, st, edges=[(0x401010, 0x401100, "data")])
    _host(ix, st)
    p = _plug(ix, st, "alpha.dll", "bb", ["PlugInit", "PlugNotify"])
    with st.db:
        st.db.execute("DELETE FROM edge WHERE kind='fnptr'")
        st.db.execute("DELETE FROM xedge")
        st.set_meta("link_version", "3")
    fp_before = G.fingerprint(st, st.list_binaries(), "t")
    assert linking.needs_relink(st)
    art = tmp_path / "arts"
    art.mkdir()
    called = []
    linking.relink_project(st, art, after=lambda: called.append(1))
    assert not linking.needs_relink(st) and called == [1]
    assert st.db.execute("SELECT COUNT(*) FROM edge WHERE kind='fnptr' AND binary_id=?", (b,)).fetchone()[0] == 1
    assert st.db.execute("SELECT COUNT(*) FROM xedge WHERE kind='dynamic' AND dst_binary=?",
                         (p,)).fetchone()[0] == 2
    assert G.fingerprint(st, st.list_binaries(), "t") != fp_before


def test_fnptr_table_needs_a_data_section(tmp_path):
    """A pointer table inside a code section (not readable-only data) is no table."""
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    fns = [_fn(0x401500 + i * 0x20, f"Handler{i}", 0x10) for i in range(5)]
    edges = [(0x405000 + 4 * i, 0x401500 + i * 0x20, "data") for i in range(4)]       # table in .rdata
    edges += [(0x401800 + 4 * i, 0x401500 + i * 0x20, "data") for i in range(4)]      # table in .text
    edges += [(0x401010, 0x405000, "data"), (0x401404, 0x401800, "data")]
    b = _app(ix, st, fns, edges)
    q = "SELECT src_addr FROM edge WHERE kind='fnptr'"
    assert len(st.db.execute(q).fetchall()) == 8          # sections unknown: both tables count
    with st.db:
        st.set_meta(f"data_ranges:{b}", "[[4214784,4218880]]")      # 0x405000..0x406000 only
    st.link_fnptr(b)
    assert {r[0] for r in st.db.execute(q)} == {0x401010}
    assert st.db.execute("SELECT COUNT(*) FROM edge WHERE kind='fnptr'").fetchone()[0] == 4


def test_pe_data_ranges_and_record_sections(tmp_path):
    import struct
    from airlock.server import linking

    def section(name, va, size, ch):
        return struct.pack("<8sIIIIIIHHI", name, size, va, size, 0x400, 0, 0, 0, 0, ch)

    nt = struct.pack("<IHHIIIHH", 0x4550, 0x14C, 3, 0, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 28, 0x400000)          # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)            # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)             # FileAlignment
    struct.pack_into("<I", opt, 56, 0x4000)            # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)             # SizeOfHeaders
    struct.pack_into("<I", opt, 92, 16)                # NumberOfRvaAndSizes
    secs = (section(b".text", 0x1000, 0x1000, 0x60000020) + section(b".rdata", 0x2000, 0x1000, 0x40000040)
            + section(b".data", 0x3000, 0x1000, 0xC0000040))
    head = bytearray(0x200)
    struct.pack_into("<2sH", head, 0, b"MZ", 0)
    struct.pack_into("<I", head, 0x3C, 0x40)
    blob = bytes(head[:0x40]) + nt + bytes(opt) + secs
    blob = blob + bytes(0x600 - len(blob))
    f = tmp_path / "x.exe"
    f.write_bytes(blob)
    assert linking.pe_data_ranges(f) == [(0x402000, 0x403000), (0x403000, 0x404000)]   # no .text
    bad = tmp_path / "y.bin"
    bad.write_bytes(b"not a pe")
    assert linking.pe_data_ranges(bad) is None
    ctx = make_ctx(tmp_path / "c")
    ix, st = _store(ctx)
    b = _app(ix, st)
    assert st.data_ranges(b) is None
    assert linking.record_sections(st, b, f) and st.data_ranges(b) == [(0x402000, 0x403000), (0x403000, 0x404000)]
    assert not linking.record_sections(st, b, bad) and not linking.record_sections(st, b, None)
