"""Type-system facts of .NET assemblies: implementations, overrides, fields, layouts, properties, events."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock.server import dotnet as dn
from airlock.server import dotnet_meta as dm
from airlock.server.tools import dotnet as dt
from test_dotnet import CSC, add_managed, make_dn_ctx

SOURCE = """
using System;
namespace D {
  public interface ILog { void Write(string s); int Count { get; } event EventHandler Changed; }
  public interface IBase { void Ping(); }
  public interface IChild : IBase { void Pong(); }
  public abstract class A : ILog {
    public virtual void Write(string s) {} public abstract int Count { get; }
    public event EventHandler Changed; public virtual void Foo() {} public void Fire() { if (Changed != null) Changed(this, null); } }
  public class B : A { public override void Write(string s) {} public override int Count { get { return 1; } } public override void Foo() {} }
  public class C : B, IChild {
    public new virtual void Foo() {} void IBase.Ping() {} public void Pong() {}
    public int F; public static int S; public const int K = 5; public const string Name = "airlock";
    public void Use() { F = 3; S = F + S; } public int Get() { return F; } }
  public class D2 : C { public override void Foo() {} }
  public enum Color { Red = 1, Green = 2, Blue = 4 }
  [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Explicit, Size=16)]
  public struct P { [System.Runtime.InteropServices.FieldOffset(0)] public int X; [System.Runtime.InteropServices.FieldOffset(8)] public ushort Y; }
  public class G<T> : ILog { public void Write(string s) {} public int Count { get { return 0; } } public event EventHandler Changed; }
}
"""

LIB2 = """
namespace Other {
  public class Logger : D.ILog { public void Write(string s) {} public int Count { get { return 2; } }
    public event System.EventHandler Changed; }
  public class Sub : D.B { public override void Foo() {} }
}
"""


@pytest.fixture(scope="module")
def dlls(tmp_path_factory) -> tuple[Path, Path]:
    if not CSC.is_file():
        pytest.skip("needs the .NET Framework C# compiler")
    d = tmp_path_factory.mktemp("meta")
    (d / "d.cs").write_text(SOURCE, encoding="utf-8")
    (d / "o.cs").write_text(LIB2, encoding="utf-8")
    for args in (["/target:library", "/out:d.dll", "d.cs"],
                 ["/target:library", "/out:o.dll", "/reference:d.dll", "o.cs"]):
        r = subprocess.run([str(CSC), "/nologo", "/nowarn:67", *args], cwd=d, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
    return d / "d.dll", d / "o.dll"


def _names(parsed, rows):
    out = set()
    for r in rows:
        m = parsed.methods[(r[0] & 0xFFFFFF) - 1]
        out.add((parsed.types[(m.type_token & 0xFFFFFF) - 1].name, m.name, r[1], r[3]))
    return out


def test_overrides_and_implementations(dlls):
    p = dn.parse_file(dlls[0])
    got = _names(p, p.meta.overrides)
    assert ("D.B", "Write", "override", "D.A") in got
    assert ("D.B", "Foo", "override", "D.A") in got
    assert ("D.A", "Write", "impl", "D.ILog") in got
    assert ("D.A", "get_Count", "impl", "D.ILog") in got
    assert ("D.C", "Pong", "impl", "D.IChild") in got
    assert ("D.C", "D.IBase.Ping", "impl", "D.IBase") in got          # explicit MethodImpl (IBase.Ping)
    assert ("D.G`1", "Write", "impl", "D.ILog") in got
    # new virtual Foo in C starts a new slot: it overrides nothing; D2.Foo overrides C.Foo, not A.Foo
    assert not any(n == ("D.C", "Foo", "override", "D.A") for n in got)
    assert ("D.D2", "Foo", "override", "D.C") in got
    assert ("D.D2", "Foo", "override", "D.A") not in got


def test_fields_layout_constants_properties_events(dlls):
    m = dn.parse_file(dlls[0]).meta
    f = {x[2]: x for x in m.fields}
    assert f["K"][6] == "5" and "const" in f["K"][4]
    assert f["Name"][6] == '"airlock"'
    assert f["Y"][5] == 8 and f["X"][5] == 0
    assert {x[2]: x[6] for x in m.fields if x[2] in ("Red", "Green", "Blue")} == {"Red": "1", "Green": "2", "Blue": "4"}
    assert any(lay[1] == "explicit" and lay[3] == 16 for lay in m.layouts)
    assert any(pr[2] == "Count" and pr[4] and not pr[5] for pr in m.props)
    assert any(ev[2] == "Changed" and ev[4] and ev[5] for ev in m.events)


def test_field_access_scan():
    # ldsfld 0x7E, stfld 0x7D, ldflda 0x7C, call 0x28 in between
    code = bytes([0x7E, 1, 0, 0, 4, 0x28, 9, 0, 0, 6, 0x7D, 2, 0, 0, 4, 0x7C, 3, 0, 0, 4, 0x2A])
    assert dm.scan_fields(code) == [("read", 0x04000001), ("write", 0x04000002), ("read", 0x04000003)]


def test_tools(tmp_path, dlls):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, dlls[0], "d.dll")
    out = dt.dotnet_types(ctx, kind="impl", query="ILog").splitlines()
    assert any("D.A" in ln and "implements D.ILog" in ln for ln in out)
    assert any("D.G`1" in ln for ln in out)
    assert any("D.B class inherits D.A" in ln for ln in out)
    mem = dt.dotnet_types(ctx, kind="impl", query="ILog::Write").splitlines()
    assert any(ln.startswith("impl D.A::Write(string)") for ln in mem)
    assert any(ln.startswith("override D.B::Write(string)") for ln in mem)
    assert any(ln.startswith("impl D.G`1::Write(string)") for ln in mem)
    base = dt.dotnet_types(ctx, kind="impl", query="A::Foo").splitlines()
    assert any(ln.startswith("override D.B::Foo()") for ln in base)
    assert not any("D.D2" in ln for ln in base)
    types = dt.dotnet_types(ctx, query="D.C").splitlines()
    assert any(ln.startswith("type D.C class") and ": D.B, IChild" in ln for ln in types)
    fld = dt.dotnet_types(ctx, kind="field", query="D.P").splitlines()
    assert any(ln.startswith("struct D.P explicit size=16") for ln in fld)
    assert any("+0x08 ushort Y" in ln for ln in fld)
    en = dt.dotnet_types(ctx, kind="field", query="Color").splitlines()
    assert any("Green = 2" in ln for ln in en) and not any("value__" in ln for ln in en)
    acc = dt.dotnet_types(ctx, kind="field", query="C::F").splitlines()
    assert any("read by D.C::Get()" in ln for ln in acc) and any("written by D.C::Use()" in ln for ln in acc)
    assert any("property D.A::Count int get" in ln for ln in dt.dotnet_types(ctx, kind="property", query="A").splitlines())
    assert any("event D.A::Changed EventHandler add/remove" in ln
               for ln in dt.dotnet_types(ctx, kind="event", query="D.A").splitlines())


def test_across_assemblies(tmp_path, dlls):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, dlls[0], "d.dll")
    add_managed(ctx, dlls[1], "o.dll")
    mem = dt.dotnet_types(ctx, kind="impl", query="ILog::Write").splitlines()
    assert any("[o.dll]" in ln and "Other.Logger::Write(string)" in ln for ln in mem)
    foo = dt.dotnet_types(ctx, kind="impl", query="B::Foo").splitlines()
    assert any("[o.dll]" in ln and "Other.Sub::Foo()" in ln for ln in foo)
    # the label of a field operand names its type
    p = dn.parse_file(dlls[0])
    tok = next(f[0] for f in p.meta.fields if f[2] == "F")
    assert p.res.label(tok) == "D.C::F"


def test_xrefs_and_callgraph_follow_dispatch(tmp_path, dlls):
    from airlock.server.tools import core
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, dlls[0], "d.dll")
    x = core.xrefs(ctx, "d.dll!D.ILog::Write", direction="to")
    assert "impl D.A::Write(string)" in x and "impl D.G`1::Write(string)" in x and "override D.B::Write(string)" in x
    y = core.xrefs(ctx, "d.dll!D.B::Write", direction="to")
    assert "overrides D.A::Write" in y
    cg = core.callgraph(ctx, "d.dll!D.ILog::Write", direction="callees", depth=2)
    assert "D.A::Write" in cg and "(impl)" in cg and "(override)" in cg
    up = core.callgraph(ctx, "d.dll!D.A::Write", direction="callers", depth=1)
    assert "D.ILog::Write" in up and "(declaration)" in up


def test_field_edges_in_xrefs(tmp_path, dlls):
    from airlock.server.tools import core
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, dlls[0], "d.dll")
    st = ctx.indexer.store("proj")
    tok = st.db.execute("SELECT token FROM dn_field WHERE binary_id=? AND name='F'", (bid,)).fetchone()[0]
    out = core.xrefs(ctx, f"0x{tok:08x}", binary="d.dll", direction="to")
    assert "write" in out and "read" in out and "D.C::Use" in out
    frm = core.xrefs(ctx, "d.dll!D.C::Use", direction="from")
    assert "D.C::F" in frm
    by_name = core.xrefs(ctx, "C::F", direction="to")                # the Type::Field selector
    assert "D.C::Use" in by_name and "write" in by_name
    assert core.xrefs(ctx, "C::Nope", direction="to").startswith("error")


def test_native_methods_link(tmp_path, dlls):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, dlls[0], "d.dll")
    st = ctx.indexer.store("proj")
    b = st.get_binary_by_id(bid)
    tok = st.db.execute("SELECT token FROM dn_method WHERE binary_id=? AND name='Pong'", (bid,)).fetchone()[0]
    with st.db:
        st.db.execute("INSERT INTO dn_native VALUES (?,?,?,?,?)", (bid, tok, 0x1220, "Pong", "D.C"))
    assert dm.native_candidates(st, b) == [(0x400000 + 0x1220, "Pong", "D.C")]
    assert dm.link_native(st, b) == 0                       # no Ghidra function there yet
    st.insert_functions(bid, [{"entry": 0x401220, "name": "Pong", "name_state": "library", "namespace": "D.C",
                               "size": 12}])
    assert dm.link_native(st, b) == 1
    assert dm.native_target(st, bid, tok) == 0x401220
    fn = st.function_at(bid, tok)
    assert dm.native_function(st, bid, fn).entry == 0x401220
    dn.ensure(st, b, ctx.indexer.paths("proj").artifacts / b.sha256, force=True)   # a re-parse drops the native rows
    assert dm.native_target(st, bid, tok) is None


def test_reference_enum_values():
    lines = dm.reference_enum_lines("Environment.SpecialFolder")
    if not lines:
        pytest.skip("needs the .NET Framework reference assemblies")
    assert "  ApplicationData = 26" in lines


def test_schema_has_meta_tables_and_migration(tmp_path):
    import sqlite3
    from airlock.index.migrations import MIGRATIONS
    from airlock.index.store import SCHEMA_VERSION
    assert SCHEMA_VERSION >= 16 and 16 in MIGRATIONS
    db = sqlite3.connect(":memory:")
    MIGRATIONS[16](db)
    MIGRATIONS[16](db)                                        # idempotent
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"dn_rel", "dn_override", "dn_field", "dn_layout", "dn_prop", "dn_event", "dn_native"} <= names
