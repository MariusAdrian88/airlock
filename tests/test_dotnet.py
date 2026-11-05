"""dotnet set (M7): dnfile metadata, P/Invoke links, managed-only indexing, ilspycmd (no Ghidra).

The test assembly is built with the .NET Framework C# compiler (skipped when it is missing). The
real-assembly checks use System.Windows.Forms.dll from the Framework folder. ilspycmd comes from
``.venv\\dotnet-tools`` (``dotnet tool install ilspycmd --tool-path``); those tests skip without it.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pefile
import pytest

from airlock.config.loader import deep_merge, default_config_text, parse_jsonc, resolve
from airlock.index.migrations import MIGRATIONS
from airlock.index.store import SCHEMA_VERSION, Store
from airlock.projects import detect, hash_file, read_manifest, write_manifest
from airlock.server import dotnet as dn
from airlock.server import registry
from airlock.server.context import ServerContext
from airlock.server.scan import scan_program
from airlock.server.tools import core
from airlock.server.tools import dotnet as dt
from test_queue import QueueWorker, idle, make_project, states, wait_for
from test_tools import FakeWorker

CSC = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe")
SWF = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Windows.Forms.dll")
ILSPY = Path(__file__).resolve().parents[1] / ".venv" / "dotnet-tools" / "ilspycmd.exe"

SOURCE = """
using System;
using System.Runtime.InteropServices;
namespace Demo.Native {
  public static class Api {
    [DllImport("nativelib.dll", EntryPoint="DoWork", CharSet=CharSet.Ansi)] public static extern int DoWork(int a);
    [DllImport("nativelib", EntryPoint="#3")] public static extern int ByOrdinal(int a);
    [DllImport("user32.dll")] public static extern int MessageBeep(uint t);
    public static int Managed(int x) { return DoWork(x) + 1; }
  }
  [ComImport, Guid("00000000-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IFoo { void Bar(); }
  public class Holder { public class Inner { public int V; } public void Run() { } }
}
"""


@pytest.fixture(scope="session")
def managed_dll(tmp_path_factory) -> Path:
    if not CSC.is_file():
        pytest.skip("needs the .NET Framework C# compiler")
    d = tmp_path_factory.mktemp("cs")
    (d / "t.cs").write_text(SOURCE, encoding="utf-8")
    r = subprocess.run([str(CSC), "/nologo", "/target:library", "/out:t.dll", "t.cs"], cwd=d,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return d / "t.dll"


def make_dn_ctx(tmp_path, ilspy: Path | None = None) -> ServerContext:
    cfg = {"ghidra_dir": str(tmp_path / "g"), "index_dir": str(tmp_path / "data"),
           "projects_root": str(tmp_path / "projects"), "defaults": {"bulk_decompile": "lazy"}}
    if ilspy is not None:
        cfg["ilspycmd"] = str(ilspy).replace("\\", "/")
    ctx = ServerContext(config=resolve(deep_merge(parse_jsonc(default_config_text()), cfg), "dirty", None),
                        worker=FakeWorker())
    ctx.worker.project_path = str(ctx.indexer.paths("proj", create=True).ghidra)
    return ctx


def add_managed(ctx: ServerContext, dll: Path, name: str = "t.dll") -> int:
    """Register a managed assembly as a ready binary the way the indexer does, and fill its tables."""
    ix = ctx.indexer
    paths = ix.paths("proj", create=True)
    sha = hash_file(dll)
    shutil.copyfile(dll, paths.artifacts / sha)
    st = ix.store("proj")
    bid = st.upsert_binary(sha, name, original_path=str(dll), format="dotnet", arch="x86",
                           pointer_size=4, image_base=0x400000, toolchain="dotnet")
    assert dn.ensure(st, st.get_binary_by_id(bid), paths.artifacts / sha)
    ix.set_status(st, bid, "ready")
    ix.current = "proj"
    return bid


def add_native(ctx: ServerContext, name: str = "nativelib.dll") -> int:
    """A ready native binary with synthetic exports DoWork (ordinal 1) and Third (ordinal 3)."""
    ix = ctx.indexer
    ix.paths("proj", create=True)
    st = ix.store("proj")
    bid = st.upsert_binary("cd" * 32, name, format="pe32", arch="x86", pointer_size=4,
                           image_base=0x10000000, toolchain="msvc", analysis_profile="p")
    st.insert_functions(bid, [
        {"entry": 0x10001000, "name": "DoWork", "name_state": "user", "size": 0x40},
        {"entry": 0x10001100, "name": "ThirdFn", "name_state": "auto", "size": 0x20}])
    st.insert_exports(bid, [("DoWork", 1, 0x10001000), (None, 3, 0x10001100)])
    st.rebuild_fts(bid)
    ix.set_status(st, bid, "ready")
    return bid


# -- parsing ------------------------------------------------------------------------------------

def test_parse_types_methods_pinvokes(managed_dll):
    p = dn.parse_file(managed_dll)
    assert p is not None
    types = {t.name: t for t in p.types}
    assert types["Demo.Native.Api"].kind == "class" and "static" in types["Demo.Native.Api"].flags
    assert types["Demo.Native.IFoo"].kind == "interface" and "com" in types["Demo.Native.IFoo"].flags
    assert types["Demo.Native.Holder+Inner"].flags.endswith("nested")
    by_name = {m.name: m for m in p.methods}
    assert by_name["DoWork"].sig == "int(int)" and "pinvoke" in by_name["DoWork"].flags
    assert by_name["MessageBeep"].sig == "int(uint)"
    assert by_name["Managed"].sig == "int(int)" and "pinvoke" not in by_name["Managed"].flags
    pin = {x.token: x for x in p.pinvokes}
    d = pin[by_name["DoWork"].token]
    assert (d.module, d.entry, d.ordinal) == ("nativelib.dll", "DoWork", None) and "ansi" in d.flags
    o = pin[by_name["ByOrdinal"].token]
    assert (o.module, o.entry, o.ordinal) == ("nativelib", None, 3)
    assert len(p.pinvokes) == 3


def test_parse_rejects_native_pe(tmp_path):
    from test_projects import make_pe
    f = tmp_path / "n.dll"
    make_pe(f)
    assert dn.parse_file(f) is None


def test_signature_decoder():
    names = {0x02000001: "Foo", 0x01000002: "Bar"}
    # instance, 2 params, void(int, Foo&)
    blob = bytes([0x20, 2, 0x01, 0x08, 0x10, 0x12, 0x04])
    assert dn.method_sig(blob, names) == "void(int, ref Foo)"
    assert dn.method_sig(bytes([0x00, 1, 0x1D, 0x0E, 0x08]), names) == "string[](int)"
    assert dn.method_sig(b"\x00\x01", names) == "?"
    assert dn.normal_module("user32") == "user32.dll"
    assert dn.normal_module(r"C:\x\Lib.DLL") == "Lib.DLL"
    assert dn.normal_module("a.ocx") == "a.ocx"


# -- schema, versions --------------------------------------------------------------------------

def test_schema_v11_and_migration(tmp_path):
    assert SCHEMA_VERSION >= 11 and 11 in MIGRATIONS
    st = Store(tmp_path / "i.sqlite")
    cols = {t: [r[1] for r in st.db.execute(f"PRAGMA table_info({t})")]
            for t in ("dn_type", "dn_method", "dn_pinvoke")}
    assert cols["dn_pinvoke"] == ["binary_id", "token", "module", "entry", "ordinal", "flags"]
    p = tmp_path / "old.sqlite"
    s = Store(p)
    for t in cols:
        s.db.execute(f"DROP TABLE {t}")
    s.db.execute("UPDATE meta SET value='10' WHERE key='schema_version'")
    s.db.commit()
    s.close()
    s = Store(p)
    assert s.schema_version == SCHEMA_VERSION
    assert s.db.execute("SELECT COUNT(*) FROM dn_type").fetchone()[0] == 0


def test_ensure_is_versioned(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, managed_dll)
    st = ctx.indexer.store("proj")
    b = st.get_binary_by_id(bid)
    art = ctx.indexer.paths("proj").artifacts / b.sha256
    assert st.get_meta(f"dotnet_version:{bid}") == str(dn.DOTNET_VERSION)
    assert dn.ensure(st, b, art) is False                    # current: nothing to do
    st.set_meta(f"dotnet_version:{bid}", "0")                # an older analyzer wrote it
    assert dn.stale(st, bid) and dn.ensure(st, b, art) is True
    assert st.db.execute("SELECT COUNT(*) FROM dn_pinvoke WHERE binary_id=?", (bid,)).fetchone()[0] == 3
    # thunks and imports are replaced, not duplicated
    assert st.db.execute("SELECT COUNT(*) FROM function WHERE binary_id=? AND is_thunk=1", (bid,)).fetchone()[0] == 3
    assert st.db.execute("SELECT COUNT(*) FROM import WHERE binary_id=?", (bid,)).fetchone()[0] == 3


# -- links (no Ghidra) -------------------------------------------------------------------------

def test_pinvoke_links_to_project_export(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    mid = add_managed(ctx, managed_dll)
    nid = add_native(ctx)
    st = ctx.indexer.store("proj")
    st.link_cross_binary(mid, [nid])
    rows = {(r["src_addr"], r["dst_entry"], r["kind"]) for r in st.db.execute(
        "SELECT * FROM xedge WHERE src_binary=?", (mid,))}
    toks = {r["name"]: r["entry"] for r in st.db.execute(
        "SELECT name, entry FROM function WHERE binary_id=?", (mid,))}
    assert rows == {(toks["DoWork"], 0x10001000, "pinvoke"),
                    (toks["ByOrdinal"], 0x10001100, "pinvoke")}    # user32 stays an import
    imp = st.db.execute("SELECT dll, name FROM import WHERE binary_id=? AND name='MessageBeep'", (mid,)).fetchone()
    assert imp["dll"] == "user32.dll"
    # relinking is idempotent
    st.link_cross_binary(mid, [nid])
    assert st.db.execute("SELECT COUNT(*) FROM xedge WHERE kind='pinvoke'").fetchone()[0] == 2

    out = core.xrefs(ctx, "nativelib.dll!DoWork", direction="to")
    assert "[t.dll]" in out and "DoWork" in out and "pinvoke" in out
    frm = core.xrefs(ctx, "t.dll!DoWork", direction="from")
    assert "nativelib.dll!DoWork" in frm
    cg = core.callgraph(ctx, "nativelib.dll!DoWork", direction="callers")
    assert "[t.dll]" in cg and "Demo.Native.Api" in cg
    c = core.function(ctx, "t.dll!DoWork", view="c")
    assert c.startswith("error managed:") and "dotnet_decompile" in c


def test_link_when_native_arrives_later(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    mid = add_managed(ctx, managed_dll)
    st = ctx.indexer.store("proj")
    assert st.db.execute("SELECT COUNT(*) FROM xedge").fetchone()[0] == 0
    nid = add_native(ctx)
    st.link_cross_binary(nid, [mid])                          # the native binary is the new one
    assert st.db.execute("SELECT COUNT(*) FROM xedge WHERE kind='pinvoke'").fetchone()[0] == 2


# -- tools -------------------------------------------------------------------------------------

def test_dotnet_types_output(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    mid = add_managed(ctx, managed_dll)
    st = ctx.indexer.store("proj")
    st.link_cross_binary(mid, [add_native(ctx)])
    out = dt.dotnet_types(ctx).splitlines()
    assert out[0] == "dotnet_types t.dll: 4 types, 8 methods, 3 pinvokes, 1 com"
    assert "type Demo.Native.Api class public,static 4m" in out
    assert any(ln.startswith("type Demo.Native.IFoo interface public,abstract,com") for ln in out)
    assert out[-1].startswith("methods and P/Invokes:")
    pin = dt.dotnet_types(ctx, kind="pinvoke").splitlines()
    assert "pinvoke Demo.Native.Api::DoWork int(int) -> nativelib.dll!DoWork ansi => nativelib.dll!DoWork" in pin
    assert "pinvoke Demo.Native.Api::ByOrdinal int(int) -> nativelib.dll!#3 => nativelib.dll!ThirdFn" in pin
    assert "pinvoke Demo.Native.Api::MessageBeep int(uint) -> user32.dll!MessageBeep" in pin
    assert len(pin) == 1 + 3
    q = dt.dotnet_types(ctx, query="user32").splitlines()
    assert q[0].endswith("| query 'user32': 1 matches") and q[1].startswith("pinvoke ")
    m = dt.dotnet_types(ctx, query="Run").splitlines()
    assert "method Demo.Native.Holder::Run void() public,virtual" not in m
    assert any(ln.startswith("method Demo.Native.Holder::Run void() public") for ln in m)
    com = dt.dotnet_types(ctx, kind="com").splitlines()
    assert com[1].startswith("com Demo.Native.IFoo interface")
    assert dt.dotnet_types(ctx, query="zzz").splitlines()[-1] == "no matches"
    cap = dt.dotnet_types(ctx, kind="method", limit=2).splitlines()
    assert len(cap) == 4 and cap[-1].startswith("… 6 more")
    assert dt.dotnet_types(ctx, kind="bogus").startswith("error bad_args:")
    assert dt.dotnet_types(ctx, binary="nativelib.dll").startswith("error not_dotnet:")


def test_dotnet_types_no_assembly(tmp_path):
    ctx = make_dn_ctx(tmp_path)
    add_native(ctx)
    ctx.indexer.current = "proj"
    assert dt.dotnet_types(ctx).startswith("error not_dotnet:")


def test_decompile_tool_missing(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, managed_dll)
    out = dt.dotnet_decompile(ctx, "Demo.Native.Api")
    assert out.startswith("error tool_missing: ilspycmd is not configured.") and "\n" not in out
    ctx2 = make_dn_ctx(tmp_path / "b", ilspy=tmp_path / "nope" / "ilspycmd.exe")
    add_managed(ctx2, managed_dll)
    out2 = dt.dotnet_decompile(ctx2, "Demo.Native.Api")
    assert out2.startswith("error tool_missing: ilspycmd not found at ") and "\n" not in out2
    assert dt.dotnet_decompile(ctx, "").startswith("error bad_args:")


@pytest.mark.skipif(not ILSPY.is_file(), reason="needs ilspycmd in .venv\\dotnet-tools")
def test_decompile_with_ilspycmd(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path, ilspy=ILSPY)
    add_managed(ctx, managed_dll)
    out = dt.dotnet_decompile(ctx, "Demo.Native.Api")
    lines = out.splitlines()
    assert lines[0] == dn.REMINDER and lines[0].startswith("// RECONSTRUCTION")
    assert "public static class Api" in out and 'DllImport("nativelib.dll"' in out
    cache = list((ctx.indexer.paths("proj").cache / "dotnet").rglob("*.cs"))
    assert len(cache) == 1
    cache[0].write_text("// from cache\nclass X {\n\tint A() { return 1; }\n}\n", encoding="utf-8")
    again = dt.dotnet_decompile(ctx, "api")                    # suffix, ignoring case; served from the cache
    assert "from cache" in again
    mem = dt.dotnet_decompile(ctx, "Demo.Native.Api", member="A")
    assert "int A() { return 1; }" in mem and "class X" not in mem
    assert dt.dotnet_decompile(ctx, "Demo.Native.Api", member="Zzz").startswith("error not_found:")
    assert dt.dotnet_decompile(ctx, "Demo.Native.Nope").startswith("error not_found:")
    nested = dt.dotnet_decompile(ctx, "Demo.Native.Holder+Inner")
    assert "class Inner" in nested


def test_member_text():
    code = ("namespace N;\n\npublic class C\n{\n\t[A]\n\tpublic int F(int a)\n\t{\n\t\treturn a;\n\t}\n\n"
            "\t[DllImport(\"x.dll\")]\n\tpublic static extern int G(int a);\n\n\tpublic int P { get; set; }\n}\n")
    f = dn.member_text(code, "F")
    assert f.splitlines()[0] == "\t[A]" and f.rstrip().endswith("}") and "return a;" in f
    g = dn.member_text(code, "G")
    assert g.splitlines() == ["\t[DllImport(\"x.dll\")]", "\tpublic static extern int G(int a);"]
    assert dn.member_text(code, "P").strip() == "public int P { get; set; }"
    assert dn.member_text(code, "Q") is None


def test_tools_registered_and_off_by_default():
    registry.load_tool_modules()
    assert {"dotnet_types", "dotnet_decompile"} <= set(registry.IMPLEMENTED)
    cfg = resolve(parse_jsonc(default_config_text()), "dirty", None)
    assert "dotnet" in cfg.disabled_sets


# -- indexing ----------------------------------------------------------------------------------

def test_detect_and_scan_managed_only(tmp_path, managed_dll):
    info = detect(managed_dll)
    assert info.toolchain == "dotnet" and info.managed_only
    d = tmp_path / "prog"
    d.mkdir()
    shutil.copyfile(managed_dll, d / "app.exe")
    r = scan_program(d, root_exe="app.exe")
    f = r.files[0]
    assert f.dotnet and f.managed and f.code_size == 0
    assert r.options[0].est_seconds < 3          # seconds, not the 6 s Ghidra overhead
    # mixed mode: the IL-only flag cleared
    mixed = d / "mixed.dll"
    mixed.write_bytes(_clear_ilonly(managed_dll.read_bytes()))
    assert not detect(mixed).managed_only and detect(mixed).toolchain == "dotnet"
    r2 = scan_program(d, root_exe="app.exe")
    assert {x.rel_path: x.managed for x in r2.files} == {"app.exe": True, "mixed.dll": False}


def _clear_ilonly(data: bytes) -> bytes:
    pe = pefile.PE(data=data, fast_load=True)
    com = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
    off = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[com].VirtualAddress) + 16
    flags = struct.unpack_from("<I", data, off)[0] & ~1
    return data[:off] + struct.pack("<I", flags) + data[off + 4:]


def _add_entry(ctx, entries, src: Path, rel: str, group: str, code_mb: float = 0.0) -> dict:
    pp = ctx.indexer.paths("proj")
    sha = hash_file(src)
    shutil.copyfile(src, pp.artifacts / sha)
    e = {"path": rel, "group": group, "kind": "pe", "size": src.stat().st_size,
         "code_size": int(code_mb * (1 << 20)), "sha256": sha, "state": "queued"}
    man = read_manifest(pp.manifest)
    man["files"] = [*man["files"], e]
    write_manifest(pp.manifest, man)
    return e


def test_queue_indexes_managed_without_ghidra(tmp_path, managed_dll):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0)])
    e = _add_entry(ctx, entries, managed_dll, "t.dll", "own_plugin")
    ix, w = ctx.indexer, ctx.worker
    ix.enqueue("proj", [e])
    wait_for(lambda: states(ctx)["t.dll"] == "ready", 20)
    assert "t_dll" not in w.imported and not any(c[0] == "analyze" and c[1]["program"] == "t_dll"
                                                 for c in w.calls)
    st = ix.store("proj")
    b = next(x for x in st.list_binaries() if x.name == "t.dll")
    assert b.format == "dotnet" and b.toolchain == "dotnet"
    assert st.db.execute("SELECT COUNT(*) FROM dn_pinvoke WHERE binary_id=?", (b.id,)).fetchone()[0] == 3
    mf = next(f for f in read_manifest(ix.paths("proj").manifest)["files"] if f["path"] == "t.dll")
    assert mf["state"] == "ready" and mf.get("managed") and mf["code_size"] == 0
    q = ix.queue_status("proj")
    row = next(r for r in q.rows if r.name == "t.dll")
    assert row.state == "ready" and row.est_seconds is None
    idle(ctx)


def test_managed_estimate_is_seconds(tmp_path, managed_dll):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0)])
    ctx.worker.gate.clear()                                   # keep app.exe from finishing
    e = _add_entry(ctx, entries, managed_dll, "t.dll", "own_plugin")
    ix = ctx.indexer
    st = ix.store("proj")
    pp = ix.paths("proj")
    shutil.copyfile(managed_dll, pp.artifacts / e["sha256"])
    # registered, not yet run: the row is estimated with the managed constant
    sha = e["sha256"]
    bid = st.upsert_binary(sha, "t.dll", format="dotnet", toolchain="dotnet", pointer_size=4)
    ix.set_status(st, bid, "queued")
    q = ix.queue_status("proj")
    assert next(r for r in q.rows if r.name == "t.dll").est_seconds == pytest.approx(1.0)
    ctx.worker.gate.set()


def test_managed_waits_for_native_and_links_both_ways(tmp_path, managed_dll):
    """The native library is analysed (fake worker) after the assembly: its arrival links the P/Invokes."""
    ctx, entries = make_project(tmp_path, [("nativelib.dll", "core", 0.5)])
    cols = ["space", "entry", "name", "name_state", "namespace", "signature", "calling_conv", "size",
            "is_thunk", "is_external"]
    ex_cols = ["space", "name", "ordinal", "address"]
    w = ctx.worker
    w.overrides[("nativelib_dll", "functions")] = (
        cols, [["ram", 0x1000, "DoWork", "user", None, None, None, 0x40, 0, 0]])
    w.overrides[("nativelib_dll", "exports")] = (ex_cols, [["ram", "DoWork", 1, 0x1000]])
    e = _add_entry(ctx, entries, managed_dll, "t.dll", "core")
    ix = ctx.indexer
    ix.enqueue("proj", [e])
    wait_for(lambda: states(ctx).get("t.dll") == "ready", 20)
    ix.enqueue("proj", entries[:1])
    wait_for(lambda: states(ctx)["nativelib.dll"] == "ready", 30)
    idle(ctx)
    st = ix.store("proj")
    kinds = [r["kind"] for r in st.db.execute("SELECT kind FROM xedge")]
    assert kinds == ["pinvoke"]


def test_mixed_mode_keeps_ghidra_and_indexes_metadata(tmp_path, managed_dll):
    ctx, entries = make_project(tmp_path, [("app.exe", "core", 1.0)])
    mixed = tmp_path / "mixed.dll"
    mixed.write_bytes(_clear_ilonly(managed_dll.read_bytes()))
    e = _add_entry(ctx, entries, mixed, "mixed.dll", "own_plugin", 0.5)
    ix, w = ctx.indexer, ctx.worker
    ix.enqueue("proj", [e])
    wait_for(lambda: states(ctx)["mixed.dll"] == "ready", 40)
    idle(ctx)
    assert "mixed_dll" in w.imported                           # Ghidra path kept
    st = ix.store("proj")
    b = next(x for x in st.list_binaries() if x.name == "mixed.dll")
    assert b.format != "dotnet" and b.toolchain == "dotnet"
    assert st.db.execute("SELECT COUNT(*) FROM dn_pinvoke WHERE binary_id=?", (b.id,)).fetchone()[0] == 3
    assert "type Demo.Native.Api" in dt.dotnet_types(ctx, binary="mixed.dll")


def test_resume_refreshes_stale_tables(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, managed_dll)
    st = ctx.indexer.store("proj")
    st.db.execute("DELETE FROM dn_type WHERE binary_id=?", (bid,))
    st.set_meta(f"dotnet_version:{bid}", "0")
    st.db.commit()
    n = dn.ensure_project(st, ctx.indexer.paths("proj").artifacts, [bid])
    assert n == 1 and st.db.execute("SELECT COUNT(*) FROM dn_type WHERE binary_id=?", (bid,)).fetchone()[0] == 5


# -- a real framework assembly -----------------------------------------------------------------

@pytest.mark.skipif(not SWF.is_file(), reason="needs the .NET Framework folder")
def test_real_assembly_pinvokes(tmp_path):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, SWF, "System.Windows.Forms.dll")
    out = dt.dotnet_types(ctx, query="user32", kind="pinvoke", limit=5)
    lines = out.splitlines()
    assert lines[0].startswith("dotnet_types System.Windows.Forms.dll: ") and "pinvokes" in lines[0]
    assert all(ln.startswith("pinvoke ") and "-> user32.dll!" in ln for ln in lines[1:6])
    n = ctx.indexer.store("proj").db.execute(
        "SELECT COUNT(*) FROM dn_pinvoke WHERE binary_id=?", (bid,)).fetchone()[0]
    assert n > 500
    assert any("com" in ln.split() or ",com" in ln for ln in dt.dotnet_types(ctx, kind="com").splitlines()[1:])
