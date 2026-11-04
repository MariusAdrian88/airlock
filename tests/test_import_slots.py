"""Calls through import slots (CALL [IAT slot]): Ghidra reports them as reads of the slot, the index
turns them into ``call_imp`` edges (synthetic stores, invented names)."""

from __future__ import annotations

import random

from airlock import projects as P
from airlock.server import clusters as cl
from airlock.server import features as fx
from airlock.server import graph as G
from airlock.server import linking
from airlock.server.budget import estimate_tokens
from airlock.server.tools import core
from airlock.server.tools import graphtools as gt
from airlock.server.tools import map as mt
from test_linking import _add, _store
from test_tools import make_ctx
from test_xbin_tools import _fn

LL, GPA, RF = 0x402000, 0x402004, 0x402008


def _ext(entry, name):
    return {"entry": entry, "space": "EXTERNAL", "name": name, "name_state": "library",
            "is_external": True, "size": 0}


def build(tmp_path, bind=False):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    fns = [_fn(0x401000, "Main", 0x80), _fn(0x401100, "Loader", 0x80), _fn(0x401200, "Reader", 0x40),
           _fn(0x401300, "Resolve", 0x40), _fn(0x401400, "Helper", 0x40),
           _ext(1, "LoadLibraryA"), _ext(2, "GetProcAddress"), _ext(3, "ReadFile")]
    edges = [(0x401010, 0x401100, "call"), (0x401020, 0x401200, "call"), (0x401030, 0x401300, "call"),
             (0x401040, 0x401400, "call"),
             (0x401110, LL, "read"),                 # CALL dword ptr [LoadLibraryA slot]
             (0x401114, 0x403000, "read"),           # a string
             (0x401120, 0x401300, "call"),
             (0x401310, GPA, "read"),                # MOV reg,[GetProcAddress slot]; CALL reg
             (0x401314, 0x403040, "read"),           # a string
             (0x401210, RF, "read"),
             (0x401410, RF, "data"),                 # slot used from code
             (0x409000, RF, "read")]                 # from no function: not a call
    strs = [(0x403000, "ascii", "plugins\\Plug.DLL"), (0x403040, "ascii", "DoWork")]
    imps = [("kernel32.dll", "LoadLibraryA", None, LL), ("kernel32.dll", "GetProcAddress", None, GPA),
            ("kernel32.dll", "ReadFile", None, RF)]
    m = _add(ix, st, "host.exe", "aa", 0x400000, fns, edges, strs, imps)
    p = _add(ix, st, "plug.dll", "bb", 0x10000000,
             [_fn(0x10001000, "DoWork"), _fn(0x10001100, "Other")],
             exps=[("DoWork", 1, 0x10001000), ("Other", 2, 0x10001100)])
    if bind:
        pp = ctx.indexer.paths("proj")
        man = P.read_manifest(pp.manifest)
        man["files"] = [{"path": "host.exe", "group": "core", "sha256": "aa" * 32},
                        {"path": "plug.dll", "group": "own_plugin", "sha256": "bb" * 32}]
        P.write_manifest(pp.manifest, man)
        st.set_meta("link_version", str(linking.LINK_VERSION))
        assert ctx.bind_session("dirty", pp) is None
    return ctx, ix, st, m, p


def kinds(st, m):
    return sorted((r["src_addr"], r["kind"]) for r in st.db.execute(
        "SELECT src_addr, kind FROM edge WHERE binary_id=? AND dst_addr IN (?,?,?)", (m, LL, GPA, RF)))


def _read_seeds(st):
    return {r[0] for r in st.db.execute(
        "SELECT entry FROM feature_entry WHERE reason='calls ReadFile' AND depth=0")}


def test_read_to_slot_is_normalised(tmp_path):
    ctx, ix, st, m, p = build(tmp_path)
    assert kinds(st, m) == [(0x401110, "call_imp"), (0x401210, "call_imp"), (0x401310, "call_imp"),
                            (0x401410, "call_imp"), (0x409000, "read")]
    assert st.db.execute("SELECT kind FROM edge WHERE dst_addr=0x403000").fetchone()[0] == "read"
    assert st.normalise_import_edges(m) == 0                       # idempotent


def test_callers_callees_xrefs_path_to_import(tmp_path):
    ctx, ix, st, m, p = build(tmp_path, bind=True)
    rf = st.functions_by_name(m, "ReadFile")[0]
    assert [f.name for f in st.callers(rf)] == ["Reader", "Helper"]
    reader = st.functions_by_name(m, "Reader")[0]
    assert [f.name for f in st.callees(reader)] == ["ReadFile"]
    out = core.xrefs(ctx, "ReadFile", kind="call").splitlines()
    assert "call_imp" in out[0], out
    assert any("Reader" in ln for ln in out) and any("Helper" in ln for ln in out)
    assert not any("0x00409000" in ln for ln in out)
    assert "Reader" in core.callgraph(ctx, "ReadFile", direction="callers")
    assert "ReadFile" in core.callgraph(ctx, "Reader")
    out = gt.path(ctx, "Main", "ReadFile")
    assert out.startswith("path Main → ReadFile"), out
    assert "Reader" in out and "no analysed function" not in out
    g = G.build_graph(st, [m])
    assert any(name == "ReadFile" for _d, name in g.imports)


def test_dynamic_link_from_slot_reads(tmp_path):
    ctx, ix, st, m, p = build(tmp_path)
    assert linking.link_dynamic_for(st, m, [p]) == 2
    rows = {r["kind"]: r for r in st.db.execute("SELECT * FROM xedge")}
    assert rows["dynlib"]["src_addr"] == 0x401100
    assert rows["dynamic"]["src_addr"] == 0x401300 and rows["dynamic"]["dst_entry"] == 0x10001000


def test_relink_converts_old_project_without_reanalysis(tmp_path):
    ctx, ix, st, m, p = build(tmp_path)
    with st.db:   # state of a project analysed by version 2
        st.db.execute("UPDATE edge SET kind='read' WHERE kind='call_imp'")
        st.db.execute("DELETE FROM xedge")
        st.set_meta("link_version", "2")
    bins = st.list_binaries()
    fp_before = cl.fingerprint(st, bins)
    fx.derive(st)
    assert _read_seeds(st) == set()
    assert linking.needs_relink(st)
    done = []
    linking.relink_project(st, tmp_path / "arts", after=lambda: (fx.derive(st), done.append(1)))
    assert not linking.needs_relink(st) and done == [1]
    assert kinds(st, m)[0] == (0x401110, "call_imp")
    assert st.db.execute("SELECT COUNT(*) FROM xedge WHERE kind IN ('dynamic','dynlib')").fetchone()[0] == 2
    assert _read_seeds(st) == {0x401200, 0x401400}                   # ReadFile callers seed file-io
    assert cl.fingerprint(st, bins) != fp_before                     # the clusters cache is invalidated
    assert st.db.execute("SELECT COUNT(*) FROM function WHERE binary_id=?", (m,)).fetchone()[0] == 8


def test_overview_budget_large_binary(tmp_path):
    """14k functions: 3 key functions per cluster in the map, 5 in function_map, overview in budget."""
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    pp = ctx.indexer.paths("proj", create=True)
    n, group = 14000, 120
    rnd = random.Random(7)
    fns = [_fn(0x401000 + i * 0x40, f"FUN_{0x401000 + i * 0x40:08x}", 0x30) for i in range(n)]
    fns.append(_ext(1, "ReadFile"))
    edges = []
    for i in range(n):
        base = i - i % group
        for _ in range(3):
            j = base + rnd.randrange(group)
            if j != i:
                edges.append((0x401000 + i * 0x40 + 4, 0x401000 + j * 0x40, "call"))
        if rnd.random() < 0.01:
            edges.append((0x401000 + i * 0x40 + 8, 0x401000 + rnd.randrange(n) * 0x40, "call"))
        if i % 50 == 0:
            edges.append((0x401000 + i * 0x40 + 12, RF, "read"))
    _add(ix, st, "big.exe", "cc", 0x400000, fns, edges, [], [("kernel32.dll", "ReadFile", None, RF)])
    man = P.read_manifest(pp.manifest)
    man["files"] = [{"path": "big.exe", "group": "core", "sha256": "cc" * 32}]
    P.write_manifest(pp.manifest, man)
    st.set_meta("link_version", str(linking.LINK_VERSION))
    assert ctx.bind_session("dirty", pp) is None
    fx.derive_project(pp, st)
    cs = cl.clusters_for(pp, st)

    def n_keys(line):
        return len(line.split("key: ")[1].split("  ")[0].split(", "))

    lines = [ln for ln in cl.cluster_summary_lines(cs) if "key: " in ln]
    assert lines and max(n_keys(ln) for ln in lines) == 3
    assert max(n_keys(cl.cluster_line(cs, c)) for c in cl.ordered(cs) if c.key_functions()) == 5
    out = mt.overview(ctx)
    assert estimate_tokens(out) <= 2000 + 100, estimate_tokens(out)
    assert "## Subsystems" in out
    tiny = mt.overview(ctx, budget=300)                                # cut, with a cursor
    assert estimate_tokens(tiny) <= 300 + 60 and "cursor=" in tiny.splitlines()[-1]
