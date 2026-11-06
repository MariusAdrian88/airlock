""".NET round 2 fix N3: overload merging (R4), argument gaps (R9)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from airlock.server import roles
from airlock.server import targets as tg
from airlock.server.selectors import fmt_addr, resolve_function
from airlock.server.tools import core
from airlock.server.tools import dotnet as dn_tools
from test_dotnet import add_managed, make_dn_ctx
from test_dotnet_names import _build

SRC = """
namespace Demo.Proc {
  public class Worker {
    public void Kill() { }
    public void Kill(bool entireTree) { Kill(); }
    public static void Run() { new Worker().Kill(true); }
  }
  public class Other { public void Kill() { } }
}
"""


@pytest.fixture(scope="module")
def n3_dll(tmp_path_factory) -> Path:
    return _build(tmp_path_factory.mktemp("n3"), "n3", SRC)


def test_function_lists_overloads_and_shows_the_first(tmp_path, n3_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, n3_dll, "n3.dll")
    out = core.function(ctx, "Demo.Proc.Worker::Kill", view="signature")
    assert out.startswith("2 overloads of Demo.Proc.Worker::Kill:")
    assert "Kill()" in out and "Kill(bool)" in out and "error" not in out
    out = core.function(ctx, "Demo.Proc.Worker::Kill", view="c")
    assert out.startswith("2 overloads of Demo.Proc.Worker::Kill; code of the first:")
    tiny = core.function(ctx, "Demo.Proc.Worker::Kill", view="c", budget=100)
    assert "overloads of Demo.Proc.Worker::Kill" in tiny and "error ambiguous" not in tiny


def test_xrefs_and_callgraph_merge_overloads(tmp_path, n3_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, n3_dll, "n3.dll")
    xs = core.xrefs(ctx, "Demo.Proc.Worker::Kill", direction="to")
    assert xs.startswith("2 overloads of Demo.Proc.Worker::Kill merged")
    assert xs.count("== 0x0600") == 2 and "Kill(bool) ==" in xs and "Run" in xs
    cg = core.callgraph(ctx, "Demo.Proc.Worker::Kill", direction="callers")
    assert cg.startswith("2 overloads of Demo.Proc.Worker::Kill merged") and "Run" in cg


def test_different_types_stay_ambiguous(tmp_path, n3_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, n3_dll, "n3.dll")
    assert tg.overload_set(ctx, "", "Kill") is None
    assert core.xrefs(ctx, "Kill", direction="to").startswith("error ambiguous")


def test_short_selector_and_token_digits(tmp_path, n3_dll):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, n3_dll, "n3.dll")
    st = ctx.indexer.store("proj")
    for sel in ("Worker.Run", "Worker::Run", "Proc.Worker.Run"):
        r = resolve_function(st, bid, sel)
        assert r.function is not None and r.function.name == "Run", (sel, r)
    assert fmt_addr(0x06000079, 8) == "0x06000079"
    assert fmt_addr(0x06000079, 4) == "0x06000079"
    assert fmt_addr(0x140001000, 8) == "0x0000000140001000"


def test_dotnet_types_kind_aliases(tmp_path, n3_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, n3_dll, "n3.dll")
    for k in ("implementations", "interface", "interfaces", "implements"):
        out = dn_tools.dotnet_types(ctx, kind=k)
        assert "bad_args" not in out, (k, out)


def test_list_binaries_with_project_while_unbound(tmp_path, n3_dll):
    from airlock.server import registry
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, n3_dll, "n3.dll")
    ctx.indexer.current = None
    assert ctx.session.role == roles.UNBOUND
    registry.load_tool_modules()
    assert "n3.dll" in registry.call(ctx, "list_binaries", project="proj")
    assert registry.call(ctx, "list_binaries").startswith("error unbound")


def test_function_on_a_type_name_lists_members(tmp_path, n3_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, n3_dll, "n3.dll")
    out = core.function(ctx, "Worker")
    assert out.startswith("Worker is the type Demo.Proc.Worker; its members:")
    assert "Demo.Proc.Worker::Run" in out and "Demo.Proc.Other::Kill" not in out


def test_search_matches_inner_name_parts_and_strings_ignore_mnemonic(tmp_path):
    from airlock.index.store import Store
    st = Store(tmp_path / "i.sqlite")
    bid = st.upsert_binary("ab" * 32, "app.exe", format="pe32", pointer_size=4, image_base=0x400000)
    st.insert_functions(bid, [
        {"entry": 0x1000, "name": "OnToolsGeneratePasswordList", "namespace": "KeePass.Forms.MainForm",
         "name_state": "user", "size": 8},
        {"entry": 0x1100, "name": "on_tools_gen_password", "name_state": "user", "size": 8},
        {"entry": 0x1200, "name": "Unrelated", "name_state": "user", "size": 8}])
    st.insert_strings(bid, [(0x2000, "utf16le", "Generate Password &List..."), (0x2100, "utf16le", "&File")])
    st.rebuild_fts(bid)
    for q in ("GeneratePasswordList", "PasswordList", "ToolsGenerate", "Generate Password List"):
        names = {h.text.split(" ")[0] for h in st.fts_search(bid, q, kind="function")}
        assert "KeePass.Forms.MainForm::OnToolsGeneratePasswordList" in names, q
    assert any("on_tools_gen_password" in h.text for h in st.fts_search(bid, "ToolsGenPassword", kind="function"))
    assert [h.value for h in st.search_strings(bid, "Generate Password List", with_refs=False)] == [
        "Generate Password &List..."]
    assert len(st.search_strings(bid, "File", with_refs=False)) == 1
    assert st.search_strings(bid, "&Fi", with_refs=False)[0].value == "&File"
    assert [h.value for h in st.search_strings(bid, "^Generate Password List", regex=True, with_refs=False)] == [
        "Generate Password &List..."]
    st.close()


ORIGIN_SRC = """
namespace Demo {
  public class Q {
    public static int Helper() { return 1; }
    public async System.Threading.Tasks.Task<int> Go() { await System.Threading.Tasks.Task.Delay(1); return Helper(); }
    public System.Func<int> Lam() { return () => Helper(); }
  }
}
"""


def test_callers_print_the_source_method(tmp_path_factory, tmp_path):
    dll = _build(tmp_path_factory.mktemp("org"), "org", ORIGIN_SRC)
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, dll, "org.dll")
    xs = core.xrefs(ctx, "Demo.Q::Helper", direction="to")
    assert "Demo.Q::Go (async MoveNext)" in xs, xs
    assert "Demo.Q::Lam (lambda b__" in xs, xs
    cg = core.callgraph(ctx, "Demo.Q::Helper", direction="callers", depth=1)
    assert "Demo.Q::Go (async MoveNext) (0x0600" in cg and "Demo.Q::Lam (lambda b__" in cg, cg


def test_ghidra_pseudo_function_over_an_il_body_forwards_to_the_token(tmp_path):
    ctx = make_dn_ctx(tmp_path)
    ix = ctx.indexer
    ix.paths("proj", create=True)
    st = ix.store("proj")
    bid = st.upsert_binary("ef" * 32, "mixed.dll", format="pe32", arch="x64", pointer_size=8,
                           image_base=0x180000000, toolchain="dotnet", analysis_profile="p")
    st.insert_functions(bid, [
        {"entry": 0x06000017, "name": "LoadPE", "namespace": "UnmanagedPE", "name_state": "user", "size": 0},
        {"entry": 0x180001000, "name": "LoadPE", "namespace": "UnmanagedPE", "name_state": "auto", "size": 56},
        {"entry": 0x180002000, "name": "Real", "name_state": "auto", "size": 20}])
    st.set_meta(f"dn_ilmap:{bid}", "1:" + json.dumps([[0x1000, 0x1038, 0x06000017]]))
    st.rebuild_fts(bid)
    ix.set_status(st, bid, "ready")
    ix.current = "proj"
    ft = tg.resolve_target(ctx, "", "0x180001000", (tg.FUNCTION,))
    assert isinstance(ft, tg.FunctionTarget) and ft.fn.entry == 0x06000017
    assert ft.note == "IL body of UnmanagedPE::LoadPE (0x06000017) at 0x0000000180001000"
    ft = tg.resolve_target(ctx, "", "0x180001010", (tg.FUNCTION,))      # inside the body
    assert isinstance(ft, tg.FunctionTarget) and ft.fn.entry == 0x06000017
    ft = tg.resolve_target(ctx, "", "UnmanagedPE::LoadPE", (tg.FUNCTION,))    # name: token plus the body, no thunk line
    assert isinstance(ft, tg.FunctionTarget) and ft.note.startswith("IL body of UnmanagedPE::LoadPE")
    other = tg.resolve_target(ctx, "", "0x180002000", (tg.FUNCTION,))   # real native code stays
    assert isinstance(other, tg.FunctionTarget) and other.fn.entry == 0x180002000 and other.note is None
