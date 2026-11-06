"""Tools across all binaries of a project (DESIGN 7.3 rule 6, 7.4): synthetic stores, invented names."""

from __future__ import annotations

import pytest

from airlock.projects import read_manifest, write_manifest
from airlock.server.tools import core
from test_tools import fill, make_ctx


def _fn(entry, name, size=0x20, thunk=False, state="auto"):
    return {"entry": entry, "name": name, "name_state": state, "size": size,
            "is_thunk": thunk}


def _build(ctx, util_ready=True):
    """main.exe imports LoadDoc/SaveDoc from engine.dll; util.dll shares the name Init."""
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    ids = {}
    spec = {
        "main.exe": (0x400000, "aa", [
            _fn(0x401000, "main", 0x40, state="user"), _fn(0x401100, "Helper", 0x30),
            _fn(0x401200, "FUN_00401200"), _fn(0x401300, "LoadDoc", 6, True, "library"),
            _fn(0x401310, "SaveDoc", 6, True, "library")],
         [(0x401010, 0x401300, "call"), (0x401020, 0x401100, "call"),
          (0x401110, 0x401310, "call"), (0x401120, 0x402008, "call_ind"),
          (0x401300, 0x402000, "jump"), (0x401310, 0x402008, "jump")],
         [(0x403000, "ascii", "Open file failed")],
         [("engine.dll", "LoadDoc", None, 0x402000), ("engine.dll", "SaveDoc", None, 0x402008)], []),
        "engine.dll": (0x10000000, "bb", [
            _fn(0x10001000, "LoadDoc", 0x40, state="user"), _fn(0x10001100, "SaveDoc"),
            _fn(0x10001200, "Parse"), _fn(0x10001300, "Init"), _fn(0x10001400, "Render")],
         [(0x10001010, 0x10001200, "call"), (0x10001210, 0x10001300, "call")],
         [(0x10003000, "ascii", "Open document failed")], [],
         [("LoadDoc", None, 0x10001000), ("SaveDoc", None, 0x10001100),
          ("Init", None, 0x10001300), ("Render", None, 0x10001400)]),
        "util.dll": (0x20000000, "cc", [_fn(0x20001000, "Init")], [],
                     [(0x20003000, "ascii", "Open util channel")], [], []),
    }
    for name, (base, sha, fns, edges, strs, imps, exps) in spec.items():
        bid = st.upsert_binary(sha * 32, name, format="pe32", arch="x86", pointer_size=4,
                               image_base=base, toolchain="msvc", analysis_profile="p")
        ids[name] = bid
        st.insert_functions(bid, fns)
        st.insert_edges(bid, edges)
        st.link_edges(bid)
        st.insert_strings(bid, strs)
        st.insert_imports(bid, imps)
        st.insert_exports(bid, exps)
        st.rebuild_fts(bid)
    for n, bid in ids.items():
        if n == "util.dll" and not util_ready:
            ix.set_status(st, bid, "analysing")
        else:
            ix.set_status(st, bid, "ready")
    st.link_cross_binary(ids["main.exe"], [ids["engine.dll"], ids["util.dll"]])
    return st, ids


@pytest.fixture
def xctx(tmp_path):
    ctx = make_ctx(tmp_path)
    st, ids = _build(ctx)
    ctx.ids = ids
    return ctx


def test_search_prefixes_and_merge(xctx):
    out = core.search(xctx, "doc").splitlines()
    assert out[0].startswith("search 'doc': ")
    assert len(out) > 4
    assert all(ln.startswith(("[main.exe] ", "[engine.dll] ")) for ln in out[1:])
    # exact-name hits of both binaries are merged by rank, not grouped per binary
    fn = core.search(xctx, "loaddoc", kind="function").splitlines()[1:]
    assert fn == ["[main.exe] function LoadDoc 0x00401300 library,thunk,6B",
                  "[engine.dll] function LoadDoc 0x10001000 user,64B"]
    both = core.search(xctx, "open").splitlines()[1:]
    assert sorted(ln.split("]")[0] for ln in both) == ["[engine.dll", "[main.exe", "[util.dll"]


def test_search_limit_and_binary(xctx):
    assert core.search(xctx, "doc", kind="function", limit=3).splitlines()[0] == "search 'doc': 3 hits"
    one = core.search(xctx, "doc", binary="engine.dll", kind="function").splitlines()
    assert one[1:] == ["function LoadDoc 0x10001000 user,64B", "function SaveDoc 0x10001100 auto,32B"]


def test_search_skips_unready(tmp_path):
    ctx = make_ctx(tmp_path)
    _build(ctx, util_ready=False)
    out = core.search(ctx, "init", kind="function").splitlines()
    assert out[0] == "search 'init': 1 hits (1 binaries not ready, skipped)"
    assert out[1].startswith("[engine.dll] function Init")


def test_strings_across_binaries(xctx):
    out = core.strings(xctx, "open").splitlines()
    assert out[0] == "strings matching 'open': 3"
    assert [ln.split("]")[0] for ln in out[1:]] == ["[main.exe", "[engine.dll", "[util.dll"]
    assert out[1] == '[main.exe] 0x00403000 "Open file failed"  <- (no refs)'
    paged = core.strings(xctx, "open", limit=2).splitlines()   # page of 2, rest behind a cursor
    assert paged[0] == "strings matching 'open': 3" and "1 more lines. cursor=" in paged[-1]
    assert core.strings(xctx, "open", binary="util.dll") == (
        'strings matching \'open\': 1\n0x20003000 "Open util channel"  <- (no refs)')


def test_target_prefix_parsing(xctx):
    sig = core.function(xctx, "engine.dll!LoadDoc", view="signature")
    assert sig.startswith("0x10001000 LoadDoc")
    assert core.function(xctx, "ENGINE.DLL!0x10001000", view="signature") == sig
    assert core.function(xctx, "LoadDoc", binary="engine.dll", view="signature") == sig
    assert core.function(xctx, "engine.dll!LoadDoc", binary="engine.dll", view="signature") == sig
    bad = core.function(xctx, "engine.dll!LoadDoc", binary="main.exe", view="signature")
    assert bad.startswith("error bad_args:")
    # left part is no binary name: no split, the whole text is the name
    assert core.function(xctx, "nobin!Foo", view="signature").startswith("error not_found:")
    assert core.function(xctx, "engine.dll!", view="signature").startswith("error not_found:")


def test_bare_name_resolution_and_ambiguity(xctx):
    one = core.function(xctx, "Render", view="signature").splitlines()
    assert one[0] == "binary engine.dll" and one[1].startswith("0x10001400 Render")
    xctx.focus.clear()                       # the focus (7.3 rule 9) would decide: Render was just viewed
    amb = core.function(xctx, "Init", view="signature")
    assert amb.startswith("error ambiguous: 'Init' matches 2 functions: ")
    assert "engine.dll!Init 0x10001300" in amb and "util.dll!Init 0x20001000" in amb
    amb2 = core.xrefs(xctx, "LoadDoc")       # main.exe's import binds to engine.dll's definition (7.3 rule 8)
    assert amb2.splitlines()[0].startswith("xrefs to LoadDoc (0x10001000)") and "binary engine.dll" in amb2
    xctx.focus.clear()
    assert core.callgraph(xctx, "Init").startswith("error ambiguous:")
    assert core.xrefs(xctx, "Nope").startswith("error not_found:")
    assert core.xrefs(xctx, "util.dll!Init", direction="from").startswith("xrefs from Init")


def test_single_binary_project_keeps_bare_targets(tmp_path):
    ctx = make_ctx(tmp_path)
    fill(ctx)
    out = core.function(ctx, "main", view="signature")
    assert out.startswith("0x00401000 int main(void)") and "binary" not in out


def test_xrefs_cross_callers_and_resolved_target(xctx):
    out = core.xrefs(xctx, "engine.dll!LoadDoc").splitlines()
    assert out[0] == "xrefs to LoadDoc (0x10001000), 2 imports"
    assert out[1] == "  [main.exe] 0x00401300  LoadDoc                              import"
    assert out[2] == "  [main.exe] 0x00402000  engine.dll!LoadDoc                   import"
    # the thunk in the importer shows where it resolves to
    t = core.xrefs(xctx, "main.exe!LoadDoc").splitlines()
    assert t[0].startswith("xrefs to LoadDoc (0x00401300), 1 call")
    assert t[1] == "→ engine.dll!LoadDoc 0x10001000"
    assert "0x00401010  main" in t[2]
    # raw import slot
    slot = core.xrefs(xctx, "main.exe!0x402008").splitlines()
    assert "→ engine.dll!SaveDoc 0x10001100" in slot
    # direction=from on the thunk also carries the note
    assert "→ engine.dll!LoadDoc 0x10001000" in core.xrefs(xctx, "main.exe!LoadDoc", direction="from")
    # kind filter drops the cross lines
    assert "[main.exe]" not in core.xrefs(xctx, "engine.dll!LoadDoc", kind="call")
    # a non-exported function has no cross lines
    assert "[main.exe]" not in core.xrefs(xctx, "engine.dll!Parse")


def test_callgraph_callees_hop(xctx):
    out = core.callgraph(xctx, "main.exe!main", depth=4).splitlines()
    assert out[0] == "callees of main (0x00401000), depth 4"
    assert out[1:] == [
        "  Helper (0x00401100)",
        "    SaveDoc (0x00401310) [thunk]",
        "      → [engine.dll] SaveDoc (0x10001100)",
        "    → [engine.dll] SaveDoc (0x10001100) [seen]",   # Helper also calls through the slot
        "  LoadDoc (0x00401300) [thunk]",
        "    → [engine.dll] LoadDoc (0x10001000)",
        "      Parse (0x10001200)",
        "        Init (0x10001300)",
    ]
    # depth limit unchanged
    short = core.callgraph(xctx, "main.exe!main", depth=1).splitlines()
    assert short[1:] == ["  Helper (0x00401100)", "  LoadDoc (0x00401300) [thunk]"]


def test_callgraph_callers_hop(xctx):
    out = core.callgraph(xctx, "engine.dll!LoadDoc", direction="callers", depth=3).splitlines()
    assert out[0] == "callers of LoadDoc (0x10001000), depth 3"
    assert out[1:] == ["  ← [main.exe] LoadDoc (0x00401300) [thunk]", "    main (0x00401000)"]
    sd = core.callgraph(xctx, "engine.dll!SaveDoc", direction="callers", depth=3).splitlines()
    assert "  ← [main.exe] SaveDoc (0x00401310) [thunk]" in sd
    assert any("Helper (0x00401100)" in ln for ln in sd)


def test_list_binaries_and_outline_columns(xctx):
    ix = xctx.indexer
    man = ix.paths("proj").manifest
    data = read_manifest(man)
    data["files"] = [{"kind": "pe", "path": "main.exe", "sha256": "aa" * 32, "group": "core",
                      "code_size": 3 * (1 << 19), "state": "ready"},
                     {"kind": "pe", "path": "engine.dll", "sha256": "bb" * 32, "group": "own_plugin",
                      "code_size": 4096, "state": "ready"}]
    write_manifest(man, data)
    lines = core.list_binaries(xctx).splitlines()
    assert len(lines) == 3
    st = ix.store("proj")
    out_n, in_n = st.cross_counts(xctx.ids["main.exe"])
    assert out_n == 4 and in_n == 0
    assert lines[0].endswith(f" ready group=core code=1.5MB fns=5 links={out_n}/0")
    assert lines[1].endswith(" ready group=own_plugin code=4KB fns=5 links=0/4")
    assert lines[2].endswith(" ready fns=1 links=0/0")   # no manifest entry: no group, no code
    o = core.outline(xctx, "main.exe").splitlines()
    assert "exports 0" in o and "imports from project binaries: engine.dll 2" in o
    e = core.outline(xctx, "engine.dll").splitlines()
    assert "exports 4" in e and not any(x.startswith("imports from project") for x in e)
