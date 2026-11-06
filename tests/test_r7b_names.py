"""Round 7 fixes: vtable of Delphi/FPC classes, rtti / IDR / vslot names as targets, data and VMT addresses."""

from __future__ import annotations

from airlock.server import idr
from airlock.server.selectors import alias_functions, resolve_function
from airlock.server.tools import core
from airlock.server.tools import cpp as cpp_tools
from test_tools import fill, make_ctx

VMT_BASE, VMT_DER = 0x403000, 0x403100        # data addresses with edges in the fixture (0x401005 data, 0x40111c read)


def _classes(st, bid):
    """TBase (vmt 0x403000): slot 0 -> OnFoo, slot 1 -> FUN_00401200; TDerived overrides slot 0 with main."""
    db = st.db
    with db:
        db.executemany(
            "INSERT INTO dl_class(binary_id, vmt, name, parent_vmt, parent, size, unit, typeinfo, nvirtual) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [(bid, VMT_BASE, "TBase", None, "TObject", 12, "vc", 0x403400, 2),
             (bid, VMT_DER, "TDerived", VMT_BASE, "TBase", 16, "vc", 0x403500, 2)])
        db.executemany(
            "INSERT INTO dl_method(binary_id, vmt, kind, slot, name, addr) VALUES (?,?,?,?,?,?)",
            [(bid, VMT_BASE, "virtual", 0, "", 0x401100), (bid, VMT_BASE, "virtual", 1, "", 0x401200),
             (bid, VMT_DER, "virtual", 0, "", 0x401000), (bid, VMT_DER, "virtual", 1, "", 0x401200),
             (bid, VMT_BASE, "rtti-public", 0, "ExportSettings", 0x401100),
             (bid, VMT_BASE, "rtti-public", 0, "Run", 0x401200),
             (bid, VMT_DER, "rtti-public", 0, "Run", 0x401000)])


def _one(tmp_path):
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    _classes(st, bid)
    return ctx, st, bid


def test_vtable_delphi_by_name_and_address(tmp_path):
    ctx, st, bid = _one(tmp_path)
    out = cpp_tools.vtable(ctx, "TDerived").splitlines()
    assert out[0] == "TDerived : TBase unit vc vmt 0x00403100 size 16 virtual 2"
    assert out[1].startswith("[0] 0x00401000 main rtti: vc.TDerived.Run") and out[1].endswith(
        "override, introduced by TBase")
    assert out[2].startswith("[1] 0x00401200 FUN_00401200") and out[2].endswith("inherited from TBase")
    base = cpp_tools.vtable(ctx, "vc.tbase").splitlines()
    assert base[0].startswith("TBase : TObject unit vc vmt 0x00403000") and base[1].endswith("; new")
    by_vmt = cpp_tools.vtable(ctx, "0x00403100").splitlines()
    assert by_vmt == out
    inner = cpp_tools.vtable(ctx, "0x00403104").splitlines()           # the pointer of slot 1
    assert inner[2].endswith("<-") and not inner[1].endswith("<-")
    assert cpp_tools.vtable(ctx, "0x00403500").splitlines()[0].startswith("TDerived")   # type info address
    assert cpp_tools.vtable(ctx, "Nope").startswith("error not_found")
    assert cpp_tools.vtable(ctx, "T").startswith("error ambiguous")


def test_alias_names(tmp_path):
    ctx, st, bid = _one(tmp_path)
    with st.db:
        st.set_meta(f"{idr.HITS_META}:{bid}", f"401200\tSystem.Classes.TList.Add | Other.Thing (+2)\n")
    idr._parse_hits.cache_clear()
    ents = lambda t: [f.entry for f in alias_functions(st, bid, t)]       # noqa: E731
    assert ents("vc.TBase.ExportSettings") == [0x401100]
    assert ents("TBase.exportsettings") == [0x401100]
    assert ents("TBase::ExportSettings") == [0x401100]
    assert ents("TBase.Run") == [0x401200]
    assert ents("TDerived.Run") == [0x401000]
    assert ents("TBase::vslot 1") == [0x401200] and ents("TDerived::vslot 0 (+1 classes)") == [0x401000]
    assert ents("System.Classes.TList.Add") == [0x401200] and ents("TList.Add") == [0x401200]
    assert ents("Thing") == [0x401200] and ents("Other.Thing") == [0x401200]
    assert ents("TBase.Nope") == []
    r = resolve_function(st, bid, "vc.TBase.ExportSettings")
    assert r.function.entry == 0x401100 and r.note.startswith("resolved 'vc.TBase.ExportSettings' to ")
    assert resolve_function(st, bid, "TBase::vslot 0").function.entry == 0x401100
    assert resolve_function(st, bid, "nothing.here").error.startswith("error not_found")


def test_overloads_are_candidates(tmp_path):
    ctx, st, bid = _one(tmp_path)
    with st.db:
        st.db.execute("INSERT INTO dl_method(binary_id, vmt, kind, slot, name, addr) VALUES (?,?,?,?,?,?)",
                      (bid, VMT_BASE, "rtti-public", 0, "Run", 0x401100))
    r = resolve_function(st, bid, "TBase.Run")
    assert r.error.startswith("error ambiguous") and "0x00401100" in r.error and "0x00401200" in r.error
    out = core.function(ctx, "TBase.Run", view="signature")
    assert out.startswith("error ambiguous") and "0x00401100" in out


def test_tool_target_by_rtti_name(tmp_path):
    ctx, st, bid = _one(tmp_path)
    out = core.function(ctx, "vc.TBase.ExportSettings", view="signature")
    assert "resolved 'vc.TBase.ExportSettings' to CMainFrame::OnFoo" in out and "0x00401100" in out
    assert "xrefs to" in core.xrefs(ctx, "TBase::vslot 1")


def test_xrefs_and_function_on_vmt(tmp_path):
    ctx, st, bid = _one(tmp_path)
    x = core.xrefs(ctx, "0x00403000").splitlines()
    assert x[0].startswith("xrefs to 0x00403000") and "0x00403000 is the vmt of Delphi class vc.TBase" in x[2]
    t = core.xrefs(ctx, "0x00403500")                                       # type info: the refs to it and to the vmt
    assert "is the type info of Delphi class vc.TDerived" in t and "0x00401110" not in t
    assert "0x0040111c" in core.xrefs(ctx, "0x00403100")
    f = core.function(ctx, "0x00403000").splitlines()
    assert f[0] == "// 0x00403000 is the vmt of Delphi class vc.TBase"
    assert f[1].startswith("TBase : TObject unit vc vmt 0x00403000")
    assert any(ln.startswith("[1] 0x00401200") for ln in f)
    assert any(ln.startswith("rtti-public ExportSettings 0x00401100") for ln in f)
    assert "references 1" in f
    assert core.function(ctx, "0x00404000").startswith("error not_found")    # no class there


def test_data_address_across_binaries(tmp_path):
    ctx, st, bid = _one(tmp_path)
    bid2 = fill(ctx, name="b.dll", sha="cd" * 32)
    st.db.execute("DELETE FROM edge WHERE binary_id=?", (bid2,))
    st.db.commit()
    out = core.xrefs(ctx, "0x00403100")                                    # only app.exe references it
    assert "binary app.exe" in out and "0x0040111c" in out
    amb = core.xrefs(ctx, "0x00403000")                                    # app.exe: refs and class; b.dll: nothing
    assert "binary app.exe" in amb
    st.db.execute("INSERT INTO edge(binary_id, src_addr, dst_addr, kind) VALUES (?,?,?,?)",
                  (bid2, 0x401020, 0x403100, "data"))
    st.db.commit()
    both = core.xrefs(ctx, "0x00403100")
    assert both.startswith("error ambiguous") and "app.exe!0x00403100" in both and "b.dll!0x00403100" in both
