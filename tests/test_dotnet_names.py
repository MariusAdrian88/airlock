"""P19 managed overload selectors and candidates, P9 cross-assembly callers (synthetic assemblies)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock.server.selectors import parse_selector, resolve_function, sig_params
from airlock.server.tools import core
from test_dotnet import CSC, add_managed, add_native, make_dn_ctx

SRC = """
namespace Demo.Proc {
  public class Worker {
    public void Kill() { }
    public void Kill(bool entireTree) { Kill(); }
    public void Save(string path, int n) { }
    public void Save(System.Collections.Generic.List<string> items) { }
    public static void Run() { new Worker().Kill(true); }
  }
}
"""

LIB = """
namespace Lib { public class Svc { public static int Go(int x) { return x; } } }
"""
APP = """
namespace App { public class Main { public static int A() { return Lib.Svc.Go(1); }
                                    public static int B() { return Lib.Svc.Go(2); } } }
"""


def _build(d: Path, name: str, src: str, refs: tuple[str, ...] = ()) -> Path:
    if not CSC.is_file():
        pytest.skip("needs the .NET Framework C# compiler")
    (d / f"{name}.cs").write_text(src, encoding="utf-8")
    cmd = [str(CSC), "/nologo", "/target:library", f"/out:{name}.dll", *[f"/r:{r}" for r in refs], f"{name}.cs"]
    r = subprocess.run(cmd, cwd=d, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return d / f"{name}.dll"


@pytest.fixture(scope="module")
def over_dll(tmp_path_factory) -> Path:
    return _build(tmp_path_factory.mktemp("ov"), "ov", SRC)


def test_parse_selector_and_params():
    assert parse_selector("A.B::Kill(bool)") == ("A.B::Kill", ["bool"])
    assert parse_selector("A.B::Kill()") == ("A.B::Kill", [])
    assert parse_selector("A.B::Kill") == ("A.B::Kill", None)
    assert parse_selector("T::M(String, System.Int32, ref List<String>)")[1] == ["string", "int", "list<string>"]
    assert sig_params("void(string, int)") == ["string", "int"]
    assert sig_params("int(int) [user32.dll!X]") == ["int"]


def test_overloads_listed_with_signatures_and_picked_by_params(tmp_path, over_dll):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, over_dll, "ov.dll")
    st = ctx.indexer.store("proj")
    amb = resolve_function(st, bid, "Demo.Proc.Worker::Kill")
    assert amb.error is not None and amb.error.startswith("error ambiguous: 'Demo.Proc.Worker::Kill' matches 2 functions: ")
    assert "Kill(), " in amb.error and "Kill(bool)" in amb.error and "0x0600" in amb.error
    for sel, want in (("Demo.Proc.Worker::Kill()", "void()"), ("Demo.Proc.Worker::Kill(bool)", "void(bool)"),
                      ("Demo.Proc.Worker.Kill(Boolean)", "void(bool)"),
                      ("Demo.Proc.Worker::Save(String, Int32)", "void(string, int)"),
                      ("Demo.Proc.Worker::Save(List<String>)", "void(List<string>)")):
        r = resolve_function(st, bid, sel)
        assert r.function is not None and r.function.signature == want, (sel, r)
        assert r.note and r.note.startswith(f"resolved '{sel}' to ")
    nf = resolve_function(st, bid, "Demo.Proc.Worker::Kill(int)")
    assert nf.error.startswith("error not_found: no overload of 'Demo.Proc.Worker::Kill' takes (int); overloads: ")
    # a dotted name without parentheses is the same method list
    assert resolve_function(st, bid, "Demo.Proc.Worker.Run").function is not None
    assert resolve_function(st, bid, "Demo.Proc.Worker.Kill").error.startswith("error ambiguous")


def test_tools_take_the_selector(tmp_path, over_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, over_dll, "ov.dll")
    out = core.callgraph(ctx, "Demo.Proc.Worker::Run()", direction="callees")
    assert "Kill" in out and "error" not in out
    xs = core.xrefs(ctx, "Demo.Proc.Worker::Kill(bool)", direction="to")
    assert "Run" in xs
    amb = core.xrefs(ctx, "Demo.Proc.Worker::Kill", direction="to")
    assert amb.startswith("2 overloads of Demo.Proc.Worker::Kill merged") and "Kill(bool)" in amb   # N3: merged


def test_token_preferred_over_native_thunk(tmp_path, over_dll):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, over_dll, "ov.dll")
    st = ctx.indexer.store("proj")
    st.insert_functions(bid, [{"entry": 0x180071f38, "name": "Run", "name_state": "auto",
                               "namespace": "Demo.Proc.Worker", "size": 0x20}])
    st = ctx.indexer.store("proj")
    r = resolve_function(st, bid, "Demo.Proc.Worker::Run")
    assert r.function is not None and r.function.entry >> 24 == 0x06
    assert r.note is not None and r.note.startswith("native thunk 0x") and "180071f38" in r.note
    out = core.xrefs(ctx, "Demo.Proc.Worker::Run", direction="from")
    assert "native thunk" in out


def test_cross_assembly_xrefs_list_callers(tmp_path):
    lib = _build(tmp_path, "lib", LIB)
    app = _build(tmp_path, "app", APP, ("lib.dll",))
    ctx = make_dn_ctx(tmp_path / "ctx")
    lid = add_managed(ctx, lib, "lib.dll")
    aid = add_managed(ctx, app, "app.dll")
    st = ctx.indexer.store("proj")
    st.link_cross_binary(aid, [lid])
    out = core.xrefs(ctx, "lib.dll!Lib.Svc::Go", direction="to")
    lines = out.splitlines()
    assert "listed as their callers" in out
    assert sum("[app.dll]" in ln and "(via mcall)" in ln for ln in lines) == 2
    assert "App.Main::A" in out and "App.Main::B" in out
    assert not any("MemberRef" in ln or "Lib.Svc::Go" in ln.split("(via")[0].split("  ")[-1] for ln in lines[2:])
