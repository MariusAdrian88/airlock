"""Library names at call sites (server/libnames.py): unique IDR/sigdb names replace FUN_ tokens in read tools."""

from __future__ import annotations

from airlock.server import libnames, registry
from airlock.server.libnames import relabel

LB = {0x4081dc: "System.UStrCatN", 0x405814: "System.Write", 0x50a680: "Dialogs.ShowMessage"}


def test_call_keeps_address_other_tokens_bare():
    c = "FUN_004081dc(&x, 2, a, b);\nlist: FUN_00405814 thunk_FUN_0050a680 PTR_FUN_004081dc FUN_00999999(1)"
    out = relabel(c, [(LB, 4)])
    assert out.startswith("System.UStrCatN/*0x004081dc*/(&x, 2, a, b);")
    assert "list: System.Write thunk_Dialogs.ShowMessage PTR_FUN_004081dc FUN_00999999(1)" in out


def test_unique_only():
    text = "401000\tA.One\n401010\tA.Two | A.Three\n401020\tA.Dup\n401030\tA.Dup\n401040\tB.More (+4)\n401050\tU.Ok"
    assert libnames._unique(text) == {0x401000: "A.One", 0x401050: "U.Ok"}


def test_64bit_call_address_width():
    assert relabel("FUN_140001000(1)", [({0x140001000: "System.Foo"}, 8)]) == "System.Foo/*0x0000000140001000*/(1)"


class _Ix:
    def __init__(self, st):
        self.st = st

    def resolve_project(self, p):
        return "p"

    def store(self, p):
        return self.st


class _Ctx:
    def __init__(self, st):
        self.indexer = _Ix(st)


def _two_binaries():
    from airlock.index.store import Store
    st = Store(":memory:")
    a = st.upsert_binary("a" * 64, "a.exe", pointer_size=4)
    b = st.upsert_binary("b" * 64, "b.exe", pointer_size=4)
    st.set_meta(f"idr_hits:{a}", "401000	System.Foo")                 # only binary A has a hit here
    return st, a, b


def test_only_the_bound_binary_is_used():
    st, a, b = _two_binaries()
    ctx = _Ctx(st)
    ba, bb = st.get_binary_by_id(a), st.get_binary_by_id(b)
    assert libnames.Display(ctx, None, [(st, ba)])("FUN_00401000(1)") == "System.Foo/*0x00401000*/(1)"
    assert libnames.Display(ctx, None, [(st, bb)])("FUN_00401000(1)") == "FUN_00401000(1)"     # B: unrelated function
    assert libnames.Display(ctx, None, [])("FUN_00401000") == "FUN_00401000"                     # unbound, two binaries
    assert libnames.Display(ctx, None, [(st, ba), (st, bb)])("FUN_00401000") == "FUN_00401000"    # several binaries


def test_single_binary_project_without_bound():
    from airlock.index.store import Store
    st = Store(":memory:")
    a = st.upsert_binary("a" * 64, "a.exe", pointer_size=4)
    st.set_meta(f"idr_hits:{a}", "401000	System.Foo")
    assert libnames.Display(_Ctx(st), None, [])("x FUN_00401000") == "x System.Foo"


def test_budget_cut_measures_shown_text_and_cursor_keeps_raw_lines():
    from airlock.server import budget
    lines = [f"{i} call FUN_00401000 FUN_00401000" for i in range(30)]
    raw, rem_raw = budget.fit_lines(lines, 120, "code", tool="t", store=budget.CursorStore())
    tok = budget.DISPLAY.set(lambda s: s.replace("FUN_00401000", "Some.Very.Long.Library.Name.Here"))
    try:
        store = budget.CursorStore()
        shown, rem = budget.fit_lines(lines, 120, "code", tool="t", store=store)
    finally:
        budget.DISPLAY.reset(tok)
    assert rem > rem_raw                                              # longer lines: fewer fit
    assert len(shown.splitlines()) < len(raw.splitlines())
    cur = next(iter(store._items.values()))
    assert cur.lines[0].startswith(f"{30 - rem} call FUN_00401000")   # the cursor holds raw lines, none lost


def test_tool_wrapper():
    from airlock.server import budget
    seen = {}

    def impl(ctx, **k):
        seen["disp"] = budget.DISPLAY.get()
        return "FUN_00401000"
    f = registry._library_names("function", impl)
    assert f(_Ctx(_two_binaries()[0])) == "FUN_00401000"              # two binaries, none bound: untouched
    assert seen["disp"] is not None and budget.DISPLAY.get() is None
    assert registry._library_names("function", lambda ctx: "error not_found: x")(None) == "error not_found: x"
    g = lambda ctx: "FUN_00401000"
    assert registry._library_names("rename", g) is g                           # writers are not relabelled


def test_case_variants_are_one_name():
    assert libnames._unique("403910\tFPC_ANSISTR_DECR_REF | fpc_ansistr_decr_ref\n403920\tA | B") == {0x403910: "fpc_ansistr_decr_ref"}
