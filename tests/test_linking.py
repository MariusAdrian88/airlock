"""Ordinal imports, PE export ordinals and LoadLibrary/GetProcAddress links: synthetic stores
and a synthetic PE, invented names."""

from __future__ import annotations

import struct
from pathlib import Path

from airlock.server import graph as G
from airlock.server import linking
from airlock.server.projectmap import relations_lines
from airlock.server.tools import core
from test_tools import make_ctx
from test_xbin_tools import _fn


def make_dll(path: Path, funcs: dict[int, int], names: dict[str, int], base: int = 0x10000000) -> None:
    """A PE32 DLL with an export directory. ``funcs``: ordinal -> RVA; ``names``: name -> ordinal."""
    sect_rva, raw = 0x1000, 0x200
    omin = min(funcs)
    n = max(funcs) - omin + 1
    d = 0x100                                           # directory offset inside the section
    arr = d + 40
    nptr = arr + 4 * n
    nord = nptr + 4 * len(names)
    dll = nord + 2 * len(names)
    strs = dll + 16
    order = sorted(names)
    blob = bytearray(0x400)
    offs, p = {}, strs
    for nm in order:
        offs[nm] = p
        blob[p:p + len(nm) + 1] = nm.encode() + b"\0"
        p += len(nm) + 1
    blob[dll:dll + 8] = b"fake.dll"
    blob[d:d + 40] = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, sect_rva + dll, omin, n, len(names),
                                 sect_rva + arr, sect_rva + nptr, sect_rva + nord)
    for o, rva in funcs.items():
        struct.pack_into("<I", blob, arr + 4 * (o - omin), rva)
    for i, nm in enumerate(order):
        struct.pack_into("<I", blob, nptr + 4 * i, sect_rva + offs[nm])
        struct.pack_into("<H", blob, nord + 2 * i, names[nm] - omin)
    opt_size = 0xE0
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x2102)
    opt = struct.pack("<HBBIIIII", 0x10B, 0, 0, 0x400, 0, 0, 0x1000, 0x1000)
    opt += struct.pack("<II", 0x2000, base) + struct.pack("<II", 0x1000, 0x200)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0) + struct.pack("<IIII", 0, 0x2000, 0x200, 0)
    opt += struct.pack("<HH", 3, 0) + struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + struct.pack("<II", sect_rva + d, 40 + 4 * n) + b"\0" * (15 * 8)
    assert len(opt) == opt_size
    sect = struct.pack("<8sIIIIIIHHI", b".text", 0x400, sect_rva, 0x400, raw, 0, 0, 0, 0, 0x60000020)
    hdr = (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + sect).ljust(raw, b"\0")
    path.write_bytes(hdr + bytes(blob))


def test_pe_export_ordinals(tmp_path):
    p = tmp_path / "e.dll"
    make_dll(p, {1: 0x1500, 2: 0x1600, 4: 0x1700}, {"Alpha": 1, "Gamma": 4})
    base, syms = linking.pe_exports(p)
    assert base == 0x10000000
    got = {(n, o, a) for n, o, a in syms}
    assert ("Alpha", 1, 0x10001500) in got and ("Gamma", 4, 0x10001700) in got
    assert (None, 2, 0x10001600) in got


def _store(ctx):
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    return ix, st


def _add(ix, st, name, sha, base, fns, edges=(), strs=(), imps=(), exps=()):
    bid = st.upsert_binary(sha * 32, name, format="pe32", arch="x86", pointer_size=4,
                           image_base=base, toolchain="msvc", analysis_profile="p")
    st.insert_functions(bid, fns)
    st.insert_edges(bid, list(edges))
    st.link_edges(bid)
    st.insert_strings(bid, list(strs))
    st.insert_imports(bid, list(imps))
    st.insert_exports(bid, list(exps))
    st.rebuild_fts(bid)
    ix.set_status(st, bid, "ready")
    return bid


def test_ordinal_import_binds_after_pe_ordinals(tmp_path):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    m = _add(ix, st, "app.exe", "aa", 0x400000,
             [_fn(0x401000, "main"), _fn(0x401300, "Ordinal_2", 6, True, "library")],
             [(0x401010, 0x401300, "call")], [],
             [("zeta.dll", "Ordinal_2", 2, 0x402000), ("zeta.dll", "Beta", None, 0x402008)])
    z = _add(ix, st, "zeta.dll", "bb", 0x10000000,
             [_fn(0x10001500, "Alpha"), _fn(0x10001600, "Beta2"), _fn(0x10001700, "Beta")], exps=[
                 ("Alpha", None, 0x10001500), ("Beta2", None, 0x10001600), ("Beta", None, 0x10001700)])
    assert st.link_cross_binary(m, [z]) == 1            # only the named import binds
    art = tmp_path / "zeta.dll"
    make_dll(art, {1: 0x1500, 2: 0x1600, 3: 0x1700}, {"Alpha": 1, "Beta2": 2, "Beta": 3})
    got = linking.fix_export_ordinals(st, st.get_binary_by_id(z), art)
    assert got == 3
    assert {r["name"]: r["ordinal"] for r in st.exports_of(z)} == {"Alpha": 1, "Beta2": 2, "Beta": 3}
    assert st.link_cross_binary(m, [z]) == 2
    imp = st.import_at(m, 0x402000)
    assert st.import_label(imp) == "zeta.dll!Beta2 (ordinal 2)"
    assert st.import_label(st.import_at(m, 0x402008)) == "zeta.dll!Beta"
    assert [x.dst_entry for x in st.cross_from_address(m, 0x402000)] == [0x10001600]


def _dyn_build(tmp_path, with_gpa=True, lib="plugins\\Plug.DLL"):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    edges = [(0x401004, 0x403000, "data"), (0x401008, 0x401300, "call")]
    fns = [_fn(0x401000, "Loader", 0x80), _fn(0x401300, "LoadLibraryA", 6, True, "library"),
           _fn(0x401310, "GetProcAddress", 6, True, "library"), _fn(0x401200, "Resolve", 0x40)]
    strs = [(0x403000, "ascii", lib), (0x403040, "ascii", "DoWork")]
    if with_gpa:
        edges += [(0x40100c, 0x401200, "call"), (0x401210, 0x401310, "call"),
                  (0x401020, 0x403040, "read")]
    m = _add(ix, st, "host.exe", "aa", 0x400000, fns, edges, strs)
    p = _add(ix, st, "plug.dll", "bb", 0x10000000,
             [_fn(0x10001000, "DoWork"), _fn(0x10001100, "Other")],
             exps=[("DoWork", 1, 0x10001000), ("Other", 2, 0x10001100)])
    return ctx, ix, st, m, p


def test_dynamic_link_from_loadlibrary_and_getprocaddress(tmp_path):
    ctx, ix, st, m, p = _dyn_build(tmp_path)
    n = linking.link_dynamic_for(st, m, [p])
    rows = st.db.execute("SELECT src_addr, dst_entry, kind, evidence FROM xedge ORDER BY kind").fetchall()
    kinds = {r["kind"]: r for r in rows}
    assert n == 2
    assert kinds["dynamic"]["src_addr"] == 0x401200 and kinds["dynamic"]["dst_entry"] == 0x10001000
    assert 'GetProcAddress "DoWork"' in kinds["dynamic"]["evidence"] and "Plug.DLL" in kinds["dynamic"]["evidence"]
    assert kinds["dynlib"]["src_addr"] == 0x401000 and kinds["dynlib"]["dst_entry"] == -1
    assert st.cross_counts(m)[0] == 2 and st.cross_counts(p)[1] == 2


def test_binary_level_dynamic_only(tmp_path):
    ctx, ix, st, m, p = _dyn_build(tmp_path, with_gpa=False, lib="Plug.dll")
    assert linking.link_dynamic_for(st, m, [p]) == 1
    r, = st.db.execute("SELECT kind, dst_entry FROM xedge").fetchall()
    assert (r["kind"], r["dst_entry"]) == ("dynlib", -1)
    lines = relations_lines(None, st, {})
    assert any(ln.startswith("host.exe -> plug.dll: 1 via LoadLibrary (dynamic)") for ln in lines)
    st.link_cross_binary(m, [p])                        # import relinking keeps dynamic rows
    assert st.db.execute("SELECT COUNT(*) FROM xedge WHERE kind='dynlib'").fetchone()[0] == 1


def test_no_link_without_library_string(tmp_path):
    ctx, ix, st, m, p = _dyn_build(tmp_path, lib="other.dll")
    assert linking.link_dynamic_for(st, m, [p]) == 0


def test_dynamic_in_xrefs_callgraph_and_graph(tmp_path):
    ctx, ix, st, m, p = _dyn_build(tmp_path)
    linking.link_dynamic_for(st, m, [p])
    out = core.xrefs(ctx, "plug.dll!DoWork").splitlines()
    assert out[0].endswith("1 dynamic")
    assert "[host.exe]" in out[1] and "Resolve" in out[1] and out[1].endswith("dynamic")
    assert core.xrefs(ctx, "plug.dll!DoWork", kind="dynamic").splitlines()[0].endswith("1 dynamic")
    cg = core.callgraph(ctx, "host.exe!Resolve")
    assert "→ [plug.dll] DoWork" in cg and "(dynamic)" in cg
    up = core.callgraph(ctx, "plug.dll!DoWork", direction="callers")
    assert "← [host.exe] Resolve" in up and "(dynamic)" in up
    g = G.build_graph(st, [m, p])
    names = {(g.info[a][0], g.info[b][0]) for (a, b) in g.directed}
    assert ("Resolve", "DoWork") in names


def test_relink_on_old_project(tmp_path):
    ctx, ix, st, m, p = _dyn_build(tmp_path)
    assert linking.needs_relink(st)
    art = tmp_path / "arts"
    art.mkdir()
    make_dll(art / ("bb" * 32), {1: 0x1000, 2: 0x1100}, {"DoWork": 1, "Other": 2})
    st.db.execute("UPDATE export SET ordinal=NULL")
    st.db.commit()
    assert linking.relink_project(st, art) >= 2
    assert not linking.needs_relink(st)
    assert {r["ordinal"] for r in st.exports_of(p)} == {1, 2}
    assert st.db.execute("SELECT COUNT(*) FROM xedge WHERE kind='dynamic'").fetchone()[0] == 1
