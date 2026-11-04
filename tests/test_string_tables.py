"""Strings tied to functions through data tables (string_link): synthetic stores, invented names."""

from __future__ import annotations

from airlock.server import linking
from airlock.server.tools import core
from test_linking import _add, _store
from test_tools import make_ctx
from test_xbin_tools import _fn

CMDS = ["alpha", "bravo", "charlie", "delta"]


def _records(base, stride_slots=2, k=1, n=4, start_str=0x403000, start_fn=0x401100):
    """edges for n records {char* name; void (*h)()} at base (pointer size 4)."""
    edges, strs = [], []
    for i in range(n):
        slot = base + i * stride_slots * 4
        sa = start_str + i * 0x10
        edges.append((slot, sa, "data"))
        edges.append((slot + k * 4, start_fn + i * 0x100, "data"))
        strs.append((sa, "ascii", CMDS[i % 4]))
    return edges, strs


def _build(ctx, edges, strs, nfn=4):
    ix, st = _store(ctx)
    fns = [_fn(0x401000, "main", 0x40)] + [_fn(0x401100 + i * 0x100, f"FUN_{i}") for i in range(nfn)]
    bid = _add(ix, st, "app.exe", "aa", 0x400000, fns, edges, strs)
    st.link_string_tables(bid)
    return st, bid


def test_interleaved_records(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000)
    st, bid = _build(ctx, e, s)
    rows = st.db.execute("SELECT string_addr, fn_entry, table_addr, evidence FROM string_link "
                         "ORDER BY string_addr").fetchall()
    assert [(r[0], r[1]) for r in rows] == [(0x403000 + i * 0x10, 0x401100 + i * 0x100) for i in range(4)]
    assert all(r[2] == 0x404000 for r in rows) and rows[1][3] == "record stride 0x8 2/4"
    fn = st.function_at(bid, 0x401200)
    assert [x.value for x in st.table_strings(fn)] == ["bravo"]
    assert [f.entry for f in st.string_link_fns(bid, 0x403000)] == [0x401100]


def test_function_pointer_before_string_and_wider_stride(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000, stride_slots=3, k=-1, n=3)
    e = [(a, d, k) for a, d, k in e]
    # k=-1 on record 0 puts the function slot before the table start: shift the table
    st, bid = _build(ctx, [(a + 4, d, k) for a, d, k in e], s, 3)
    assert st.db.execute("SELECT COUNT(*) FROM string_link").fetchone()[0] == 3


def test_two_records_are_not_a_table(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000, n=2)
    st, _ = _build(ctx, e, s)
    assert st.db.execute("SELECT COUNT(*) FROM string_link").fetchone()[0] == 0


def test_irregular_stride_breaks_run(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000, n=4)
    e = [(a + (8 if a > 0x404010 else 0), d, k) for a, d, k in e]    # record 3+ shifted: 2 + 2
    st, _ = _build(ctx, e, s)
    assert st.db.execute("SELECT COUNT(*) FROM string_link").fetchone()[0] == 0


def test_parallel_arrays(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = [], []
    for i in range(4):
        e.append((0x404000 + i * 4, 0x403000 + i * 0x10, "data"))
        e.append((0x404010 + i * 4, 0x401100 + i * 0x100, "data"))
        s.append((0x403000 + i * 0x10, "ascii", CMDS[i]))
    st, bid = _build(ctx, e, s)
    rows = st.db.execute("SELECT string_addr, fn_entry, evidence FROM string_link ORDER BY string_addr").fetchall()
    assert [(r[0], r[1]) for r in rows] == [(0x403000 + i * 0x10, 0x401100 + i * 0x100) for i in range(4)]
    assert rows[0][2] == "parallel arrays 1/4"


def test_code_references_do_not_count_and_relink_rebuilds(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000)
    st, bid = _build(ctx, e, s)
    st.db.execute("DELETE FROM string_link")
    st.db.commit()
    st.link_edges(bid)                           # the link phase rebuilds it
    assert st.db.execute("SELECT COUNT(*) FROM string_link").fetchone()[0] == 4
    st.clear_binary_data(bid)
    assert st.db.execute("SELECT COUNT(*) FROM string_link").fetchone()[0] == 0


def test_tools_show_table_link(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000)
    _build(ctx, e, s)
    out = core.strings(ctx, "bravo")
    assert "(no refs)  table: FUN_1" in out
    xr = core.xrefs(ctx, "0x00403010")
    assert "FUN_1" in xr and " table (record stride 0x8 2/4)" in xr
    assert "table" not in core.xrefs(ctx, "0x00403010", kind="read")
    assert "FUN_1" in core.xrefs(ctx, "0x00403010", kind="table")


def test_old_project_relinks(tmp_path):
    ctx = make_ctx(tmp_path)
    e, s = _records(0x404000)
    st, bid = _build(ctx, e, s)
    st.db.execute("DELETE FROM string_link")
    st.set_meta("link_version", str(linking.LINK_VERSION - 1))
    st.db.commit()
    assert linking.needs_relink(st)
    linking.relink_project(st, tmp_path)
    assert st.db.execute("SELECT COUNT(*) FROM string_link").fetchone()[0] == 4
