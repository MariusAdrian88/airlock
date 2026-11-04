"""Shared target resolution (DESIGN 7.3 table): every accepted form per tool, imports across
binaries, statically linked library functions, error texts. Synthetic stores, invented names
except generic API names."""

from __future__ import annotations

import pytest

from airlock.server import targets as tg
from airlock.server.tools import core
from airlock.server.tools import fmap
from airlock.server.tools import map as mt
from test_linking import _add, _store
from test_tools import make_ctx
from test_xbin_tools import _fn

RF, CF = 0x402000, 0x402004


def _stub(entry, name, ns="KERNEL32.DLL"):
    return {"entry": entry, "space": "EXTERNAL", "name": name, "namespace": ns,
            "name_state": "library", "is_external": True, "size": 0}


def build(tmp_path, static=False):
    """host.exe and plug.dll import ReadFile from KERNEL32; tool.exe imports nothing."""
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    ids = {}
    ids["host.exe"] = _add(
        ix, st, "host.exe", "aa", 0x400000,
        [_fn(0x401000, "Main", 0x40), _fn(0x401100, "Reader", 0x40), _fn(0x401200, "Writer", 0x40),
         _fn(0x401300, "ReadFile", 6, True, "library"), _stub(1, "ReadFile"), _stub(2, "CreateFileW")],
        [(0x401010, 0x401300, "call"), (0x401110, RF, "read"), (0x401300, RF, "jump"),
         (0x401210, CF, "read")], [],
        [("kernel32.dll", "ReadFile", None, RF), ("kernel32.dll", "CreateFileW", None, CF)])
    ids["plug.dll"] = _add(
        ix, st, "plug.dll", "bb", 0x10000000,
        [_fn(0x10001000, "Worker", 0x40), _fn(0x10001100, "Other", 0x40)],
        [(0x10001010, 0x10002000, "read"), (0x10001110, 0x10002004, "read")], [],
        [("KERNEL32.DLL", "ReadFile", None, 0x10002000), ("KERNEL32.DLL", "CreateFileA", None, 0x10002004)])
    ids["tool.exe"] = _add(ix, st, "tool.exe", "cc", 0x500000,
                           [_fn(0x501000, "Main", 0x40), _fn(0x501100, "Solo", 0x40)],
                           strs=[(0x503000, "ascii", "Open the thing")])
    if static:
        ids["lib.exe"] = _add(ix, st, "lib.exe", "dd", 0x600000,
                              [_fn(0x601000, "ReadFile", 0x40, state="library"),
                               _fn(0x601100, "StaticUser", 0x40)],
                              [(0x601110, 0x601000, "call")])
    return ctx, st, ids


@pytest.fixture
def world(tmp_path):
    return build(tmp_path)


def _head(out):
    return out.splitlines()[0]


# -- xrefs: every form of the import --------------------------------------------------------------

@pytest.mark.parametrize("form", ["ReadFile", "KERNEL32!ReadFile", "KERNEL32.DLL!ReadFile",
                                  "kernel32.dll!readfile", "KERNEL32.DLL::ReadFile", "__imp_ReadFile"])
def test_xrefs_import_every_form_merges_binaries(world, form):
    out = core.xrefs(world[0], form).splitlines()
    assert out[0] == "xrefs to KERNEL32!ReadFile (import, 2 binaries), 3 refs: 1 call, 2 call_imp"
    assert [ln.split()[:3] for ln in out[1:]] == [
        ["[host.exe]", "0x00401010", "Main"], ["[host.exe]", "0x00401110", "Reader"],
        ["[plug.dll]", "0x10001010", "Worker"]]


def test_xrefs_import_in_one_binary_keeps_plain_layout(world):
    ctx = world[0]
    out = core.xrefs(ctx, "host.exe!ReadFile").splitlines()
    # the thunk's own jump to the slot is not a reference
    assert out[0] == "xrefs to ReadFile (0x00401300), 2 refs: 1 call, 1 call_imp"
    assert [ln.split()[:2] for ln in out[1:]] == [["0x00401010", "Main"], ["0x00401110", "Reader"]]
    one = core.xrefs(ctx, "ReadFile", binary="plug.dll").splitlines()
    assert one[0] == "xrefs to KERNEL32!ReadFile, 1 call_imp" and one[1].split()[:2] == ["0x10001010", "Worker"]
    # the only binary of the three with the import: a binary note, no prefix
    cf = core.xrefs(ctx, "CreateFileW").splitlines()
    assert cf[0].startswith("xrefs to KERNEL32.DLL::CreateFileW (") and cf[1] == "binary host.exe"
    assert "Writer" in cf[2] and "[host.exe]" not in cf[2]


def test_xrefs_import_a_w_variants_and_kind(world):
    ctx = world[0]
    out = core.xrefs(ctx, "CreateFile").splitlines()          # CreateFileA in plug, CreateFileW in host
    assert "(import, 2 binaries)" in out[0]
    assert any(ln.startswith("  [host.exe]") for ln in out) and any(ln.startswith("  [plug.dll]") for ln in out)
    assert _head(core.xrefs(ctx, "ReadFile", kind="data")) == (
        "xrefs to KERNEL32!ReadFile (import, 2 binaries), no references")


def test_xrefs_direction_from_on_import(world):
    ctx = world[0]
    assert core.xrefs(ctx, "plug.dll!ReadFile", direction="from") == (
        "error external: KERNEL32!ReadFile is an imported function with no code. "
        "Use direction=to to see its callers.")
    assert _head(core.xrefs(ctx, "host.exe!ReadFile", direction="from")).startswith("xrefs from ReadFile")
    assert _head(core.xrefs(ctx, "KERNEL32!ReadFile", direction="from")) == "xrefs from ReadFile (0x00401300), 1 jump"


def test_xrefs_function_and_address_forms(world):
    ctx = world[0]
    assert _head(core.xrefs(ctx, "host.exe!Main")).startswith("xrefs to Main (0x00401000)")
    assert _head(core.xrefs(ctx, "host.exe!0x401000")).startswith("xrefs to Main (0x00401000)")
    assert core.xrefs(ctx, "host.exe!0x401004").splitlines()[1].startswith("resolved from interior address")
    raw = core.xrefs(ctx, "host.exe!0x402000").splitlines()
    assert raw[1] == "no function starts here; showing raw references"
    assert core.xrefs(ctx, "Worker").splitlines()[1] == "binary plug.dll"      # unique across binaries
    amb = core.xrefs(ctx, "Main")
    assert amb.startswith("error ambiguous: 'Main' matches 2 functions: ")
    assert "host.exe!Main 0x00401000" in amb and "tool.exe!Main 0x00501000" in amb
    assert "\n" not in amb and amb.endswith("Retry with binary!name or binary!address.")
    nf = core.xrefs(ctx, "Nope")
    assert nf.startswith("error not_found: no function or import named 'Nope' in 3 ready binaries.")


# -- callgraph -------------------------------------------------------------------------------------

def test_callgraph_callers_of_import_across_binaries(world):
    ctx = world[0]
    out = core.callgraph(ctx, "KERNEL32!ReadFile", direction="callers", depth=2).splitlines()
    assert out[0] == "callers of KERNEL32!ReadFile (import, 2 binaries), depth 2"
    assert out[1:] == ["  [host.exe] Main (0x00401000)", "  [host.exe] Reader (0x00401100)",
                       "  [plug.dll] Worker (0x10001000)"]
    for form in ("ReadFile", "kernel32.dll!ReadFile", "KERNEL32.DLL::ReadFile"):
        assert core.callgraph(ctx, form, direction="callers", depth=2).splitlines()[0] == out[0]
    one = core.callgraph(ctx, "host.exe!ReadFile", direction="callers").splitlines()
    assert one[0] == "callers of ReadFile (0x00401300), depth 2"
    assert one[1:] == ["  Main (0x00401000)", "  Reader (0x00401100)"]
    # an import has no callees of its own
    assert core.callgraph(ctx, "plug.dll!ReadFile").splitlines()[-1] == "  (none)"
    assert core.callgraph(ctx, "Main").startswith("error ambiguous:")
    assert _head(core.callgraph(ctx, "plug.dll!Worker")) == "callees of Worker (0x10001000), depth 2"


# -- function --------------------------------------------------------------------------------------

def test_function_accepts_functions_and_import_stubs(world):
    ctx = world[0]
    assert core.function(ctx, "host.exe!Main", view="signature").startswith("0x00401000 Main")
    thunk = core.function(ctx, "KERNEL32!ReadFile", view="signature").splitlines()
    assert thunk[0] == "binary host.exe" and thunk[1].startswith("0x00401300 ReadFile")   # the one thunk
    assert core.function(ctx, "host.exe!CreateFileW") == (
        "error external: KERNEL32.DLL::CreateFileW is an imported function with no code. "
        "Use xrefs on it to see its callers.")
    assert core.function(ctx, "plug.dll!ReadFile") == (      # import row only, no stub
        "error external: KERNEL32!ReadFile is an imported function with no code. "
        "Use xrefs on it to see its callers.")
    assert core.function(ctx, "Main").startswith("error ambiguous: 'Main'")
    assert core.function(ctx, "Nope").startswith("error not_found: no function or import named 'Nope'")
    assert core.function(ctx, "").startswith("error bad_target:")


def test_function_static_library_function(tmp_path):
    ctx = build(tmp_path, static=True)[0]
    out = core.function(ctx, "KERNEL32!ReadFile", view="signature").splitlines()
    assert out[0] == "binary lib.exe" and out[1].startswith("0x00601000 ReadFile")
    amb = core.function(ctx, "ReadFile", view="signature")        # a real function and imports elsewhere
    assert amb.startswith("error ambiguous: 'ReadFile' matches 3 functions: ")
    assert "lib.exe!ReadFile 0x00601000" in amb and "host.exe!ReadFile 0x00401300" in amb
    assert core.function(ctx, "lib.exe!ReadFile", view="signature").startswith("0x00601000 ReadFile")
    x = core.xrefs(ctx, "KERNEL32!ReadFile")                       # the library copy's callers count too
    assert "(import, 3 binaries)" in _head(x) and "[lib.exe] 0x00601110  StaticUser" in x


# -- other policies ---------------------------------------------------------------------------------

def test_feature_define_takes_functions_only(world):
    ctx = world[0]
    assert ctx.bind_session("dirty", ctx.indexer.paths("proj")) is None
    err = mt.feature_define(ctx, "reads", "Reads", functions="KERNEL32!ReadFile")
    assert err == ("error bad_target: 'KERNEL32!ReadFile' is an import (KERNEL32!ReadFile) with no code of "
                   "its own, but this tool takes a function name or address. "
                   "Use xrefs on it, or pass a function that calls it.")
    assert mt.feature_define(ctx, "reads", "Reads", functions="Main").startswith("error ambiguous:")
    ok = mt.feature_define(ctx, "reads", "Reads", functions="host.exe!Main, plug.dll!0x10001010")
    assert ok.startswith("feature reads defined: Reads | 2 functions added")


def test_function_map_scope_of_import(world):
    ctx, _st, ids = world
    imp = tg.resolve_target(ctx, "", "KERNEL32!ReadFile", (tg.FUNCTION, tg.IMPORT))
    assert isinstance(imp, tg.ImportTarget) and len(imp.bindings) == 2

    class C:
        def __init__(self, cid):
            self.id = cid

    class CS:
        def of(self, key):
            return C("C1" if key[0] == ids["host.exe"] else "C2")

    class Empty:
        def of(self, key):
            return None

    pred, mem, head, err = fmap._import_scope(CS(), imp)
    assert err is None and mem is None
    assert head == ["KERNEL32!ReadFile is called from C1 (2 callers), C2 (1 callers)"]
    assert pred(C("C1")) and not pred(C("C9"))
    assert fmap._import_scope(Empty(), imp)[3].startswith("error not_clustered:")


def test_resolve_target_kinds_and_errors(world):
    ctx, st, _ids = world
    rt = tg.resolve_target
    assert isinstance(rt(ctx, "", "KERNEL32!ReadFile", (tg.IMPORT,)), tg.ImportTarget)
    s = rt(ctx, "", '"Open the thing"', (tg.STRING,))
    assert isinstance(s, tg.StringTarget) and s.how == "exact" and s.matches[0][1].address == 0x503000
    sub = rt(ctx, "", "Open the", (tg.STRING,))
    assert isinstance(sub, tg.StringTarget) and sub.how == "substring"
    bad = rt(ctx, "", '"Open"', (tg.FUNCTION,))
    assert bad.startswith("error bad_target:") and "\n" not in bad
    assert rt(ctx, "", '"zzz"', (tg.STRING,)).startswith("error not_found: no string matching")
    a = rt(ctx, "host.exe", "0x402000", (tg.FUNCTION, tg.ADDRESS))
    assert isinstance(a, tg.AddressTarget) and a.value == 0x402000
    assert rt(ctx, "host.exe", "0x402000", (tg.FUNCTION,)).startswith("error not_found:")
    assert rt(ctx, "plug.dll", "host.exe!Main", (tg.FUNCTION,)) == (
        "error bad_args: target names binary 'host.exe' but binary='plug.dll'. Pass one of them.")
    st.define_feature("reading", "Reading", "", "2026-01-01T00:00:00Z")
    f = rt(ctx, "", "reading", (tg.FEATURE,))
    assert isinstance(f, tg.FeatureTarget) and f.key == "reading"
    assert rt(ctx, "", "reading", (tg.FUNCTION,)).startswith("error not_found:")
    assert rt(ctx, "", "C7", (tg.CLUSTER,)).startswith("error not_found:")
    # a DLL that nothing imports from is not a DLL hint: the whole text is a name
    assert rt(ctx, "", "NOSUCH!ReadFile", (tg.FUNCTION, tg.IMPORT)).startswith("error not_found:")
