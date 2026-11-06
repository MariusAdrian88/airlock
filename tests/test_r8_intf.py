"""Round 8 (N1): Delphi interface tables (vmtIntfTable), IMT thunks, vtable / function / xrefs on interface
addresses, and interface-call comments in decompiled C. Synthetic 32-bit and 64-bit PEs; all names invented."""

from __future__ import annotations

import re
import struct

import pytest

from airlock.server import delphi, intflabel
from airlock.server.cpp import Image
from airlock.server.tools import core
from airlock.server.tools import cpp as cpp_tools
from airlock.server.vcallnames import DbClasses, annotate
from test_delphi import TEXT_VA, Pe, _ss
from test_tools import make_ctx

GUID = "{B4F1A2C3-1111-2222-3333-444455556666}"
GUID2 = "{0A0B0C0D-0000-1111-2222-333344445555}"


def guid_bytes(text: str) -> bytes:
    d1, d2, d3 = (int(x, 16) for x in (text[1:9], text[10:14], text[15:19]))
    return struct.pack("<IHH", d1, d2, d3) + bytes.fromhex(text[20:24] + text[25:37])


def emit(pe: Pe, build) -> int:
    """Write machine code that is built from its own address into the text section; return the address."""
    at = pe.tpos
    va = pe.base + TEXT_VA + at
    code = build(va)
    pe.text[at:at + len(code)] = code
    pe.tpos += (len(code) + 15) // 16 * 16
    return va


def thunk(pe: Pe, kind: str, arg, adjust: int = -12) -> int:
    """An IMT entry: ``jmp`` to a code address after the Self adjustment, or ``virt`` through VMT byte offset ``arg``."""
    ps = pe.ps
    pre = (bytes([0x83, 0xC0]) if ps == 4 else bytes([0x48, 0x83, 0xC1])) + struct.pack("<b", adjust)
    if kind == "jmp":
        return emit(pe, lambda va: pre + b"\xe9" + struct.pack("<i", arg - (va + len(pre) + 5)))
    if ps == 4:
        return emit(pe, lambda va: pre + bytes([0x50, 0x8B, 0x00, 0x8B, 0x40, arg, 0x87, 0x04, 0x24, 0xC3]))
    return emit(pe, lambda va: pre + bytes([0x48, 0x8B, 0x01, 0xFF, 0x60, arg]))


def add_interface(pe: Pe, cls: str, gtext: str, iname: str, slots: list[int], off: int) -> tuple[int, int]:
    """Give the class ``cls`` an interface table with one interface; ``slots`` are the IMT entries. Returns the
    address of the table and of the IMT. Also writes the type info of the interface."""
    ps = pe.ps
    blob = bytes([15]) + _ss(iname) + pe.p(0) + bytes([1]) + guid_bytes(gtext) + _ss("unit1")
    pe.put(pe.alloc(len(blob), 1), blob)
    imt = pe.alloc(ps * len(slots))
    pe.put(imt, b"".join(pe.p(s) for s in slots))
    ent = guid_bytes(gtext) + pe.p(imt) + (struct.pack("<ii", off, 0) if ps == 4 else struct.pack("<qq", off, 0))
    tab = pe.alloc(ps + len(ent), ps)
    pe.put(tab, struct.pack("<I", 1).ljust(ps, b"\0") + ent)
    vmt = pe.vmts[cls]
    pe.put(vmt - pe.slots * ps + ps, pe.p(tab))
    return tab, imt


def build_pe(path, psize: int):
    pe = Pe(psize)
    pe.klass("TObject", None, "System", 8, virtuals=("Dtor",))
    pe.klass("TBase", "TObject", "vc", 16, published=("Greet", "Count"), virtuals=("Dtor", "Init", "Make"))
    com = [pe.stub(f"TBase.com{i}") for i in range(3)]
    slots = [thunk(pe, "jmp", c) for c in com]
    slots.append(thunk(pe, "jmp", pe.code["TBase.Greet"]))                    # Greet: a plain method
    slots.append(thunk(pe, "virt", 2 * psize))                                # Make: through virtual slot 2
    slots.append(pe.stub("TBase.direct"))                                     # no adjustment: the method itself
    tab, imt = add_interface(pe, "TBase", GUID, "IGreeter", slots, 3 * psize)
    pe.write(path)
    return pe, tab, imt


@pytest.mark.parametrize("psize", [4, 8])
def test_delphi_interface_table(tmp_path, psize):
    pe, tab, imt = build_pe(tmp_path / "a.exe", psize)
    classes, _forms = delphi.parse_file(tmp_path / "a.exe")
    base = {c.name: c for c in classes}["TBase"]
    rows = {(m.kind, m.slot): m for m in base.methods if m.kind in delphi.INTF_KINDS}
    assert rows[("interface-tab", 1)].addr == tab
    t = rows[("interface-table", 0)]
    assert t.addr == imt
    assert delphi.parse_intf_table(t.name) == (
        "IGreeter", GUID, 3 * psize, 6, delphi.parse_intf_table(t.name).typeinfo)
    assert delphi.parse_intf_table(t.name).typeinfo != 0
    names = [m.name for m in base.methods if m.kind == "interface"]
    assert names == ["IGreeter.QueryInterface", "IGreeter._AddRef", "IGreeter._Release", "IGreeter.Greet",
                     "IGreeter.#4", "IGreeter.#5"]
    tg = {k: m.addr for (kind, k), m in rows.items() if kind == "interface-target"}
    assert tg[3] == pe.code["TBase.Greet"]                                   # ADD Self,-12; JMP Greet
    assert tg[4] == pe.code["TBase.v2_Make"]                                 # through the VMT: the class's own slot 2
    assert tg[5] == pe.code["TBase.direct"]                                  # the entry is the method
    assert [(f.name, f.offset) for f in base.fields if f.type == "interface"] == [("IGreeter", 3 * psize)]


def test_zero_guid_and_unknown_thunk(tmp_path):
    pe = Pe(4)
    pe.klass("TObject", None, "System", 8, virtuals=("Dtor",))
    pe.klass("TBase", "TObject", "vc", 16, virtuals=("Dtor",))
    odd = emit(pe, lambda va: bytes([0x83, 0xC0, 0xF4, 0x90, 0xC3]))          # adjustment, then no known body
    add_interface(pe, "TBase", "{00000000-0000-0000-0000-000000000000}", "IGone", [odd], 8)
    pe.write(tmp_path / "a.exe")
    classes, _ = delphi.parse_file(tmp_path / "a.exe")
    base = {c.name: c for c in classes}["TBase"]
    tab = [m for m in base.methods if m.kind == "interface-table"][0]
    assert tab.name.startswith("intf_") and " - offset 8 slots 1" in tab.name        # anonymous interface: no GUID
    assert not [m for m in base.methods if m.kind == "interface-target"]              # unknown thunk: no target


# ── tools ──────────────────────────────────────────────────────────────────

@pytest.fixture
def proj(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "ab" * 32
    pe, tab, imt = build_pe(art / sha, 4)
    bid = st.upsert_binary(sha, "vc.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="delphi", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert delphi.ensure(st, st.get_binary_by_id(bid), art / sha)
    return ctx, st, bid, pe, tab, imt


def test_vtable_lists_interfaces(proj):
    ctx, st, bid, pe, tab, imt = proj
    out = cpp_tools.vtable(ctx, "TBase").splitlines()
    head = next(i for i, ln in enumerate(out) if ln.startswith("interface "))
    assert out[head] == f"interface IGreeter {GUID} imt 0x{imt:08x} offset 12 slots 6"
    greet = pe.code["TBase.Greet"]
    assert re.fullmatch(rf"  \[3\] 0x[0-9a-f]{{8}} Greet -> 0x{greet:08x} TBase\.Greet", out[head + 4])
    assert out[head + 5].split("-> ")[1].endswith("0x%08x" % pe.code["TBase.v2_Make"])     # virtual: no name known
    assert out[head + 1].startswith("  [0] ") and " QueryInterface -> " in out[head + 1]


def test_vtable_function_xrefs_on_interface_addresses(proj):
    ctx, st, bid, pe, tab, imt = proj
    ps = 4
    for addr in (imt, imt + 3 * ps, tab):
        out = cpp_tools.vtable(ctx, f"0x{addr:08x}").splitlines()
        assert out[0].startswith("TBase : TObject unit vc vmt ") and any(ln.startswith("interface IGreeter") for ln in out)
        assert not any(ln.startswith("[0]") for ln in out)                        # the class slots are not repeated
    marked = cpp_tools.vtable(ctx, f"0x{imt + 3 * ps:08x}").splitlines()
    assert [ln for ln in marked if ln.endswith("<-")][0].startswith("  [3] ")
    fn = core.function(ctx, f"0x{imt:08x}")
    assert f"0x{imt:08x} is the interface method table of IGreeter of Delphi class vc.TBase" in fn
    assert "interface IGreeter" in fn
    fn = core.function(ctx, f"0x{tab:08x}")
    assert f"0x{tab:08x} is the interface table of Delphi class vc.TBase" in fn
    x = core.xrefs(ctx, f"0x{imt:08x}")
    assert f"0x{imt:08x} is the interface method table of IGreeter of Delphi class vc.TBase" in x
    vmt = pe.vmts["TBase"]
    hdr = vmt - 4 * 4                                                         # inside the header before the VMT
    assert "is in the header before the VMT of Delphi class vc.TBase" in core.function(ctx, f"0x{hdr:08x}")
    assert cpp_tools.vtable(ctx, f"0x{hdr:08x}").startswith("TBase : TObject")
    far = cpp_tools.vtable(ctx, f"0x{pe.vmts['TObject'] - 30 * 4:08x}")
    assert not far.startswith("TBase")


# ── interface calls in decompiled C ────────────────────────────────────────

C_INTF = """void FUN_00401000(int *param_1,undefined4 param_2)

{
  local_8 = param_1;
  System.@IntfAddRef/*0x0040b490*/((int *)param_1);
  vmt_c_adc_0(local_8,param_2,&local_10);
  vmt_4_ad_0(local_8);
  vmt_28_ad_0(local_8);
  vmt_c_adc_0(param_2,&local_10);
  return;
}
"""


def _cls(proj):
    ctx, st, bid, pe, tab, imt = proj
    return DbClasses(st, st.get_binary_by_id(bid), 0x401000)


def test_interface_call_comment(proj):
    out = annotate(C_INTF, _cls(proj))
    greet = "IGreeter.Greet -> TBase.Greet"
    assert f"vmt_c_adc_0/*{greet}*/(local_8,param_2,&local_10);" in out
    assert "vmt_4_ad_0/*intf slot 1: _AddRef*/(local_8);" in out                      # COM slots keep their names
    assert "vmt_28_ad_0/*intf slot 10*/(local_8);" in out                             # no interface has slot 10
    assert "vslot" not in out.split("vmt_28_ad_0")[0].split("vmt_c_adc_0")[1]
    assert "vmt_c_adc_0/*" in out and out.count("IGreeter.Greet") == 1                # param_2 is no interface variable
    # the same call on a variable that is not an interface keeps the class label
    plain = annotate(C_INTF.replace("System.@IntfAddRef/*0x0040b490*/((int *)param_1);", ""), _cls(proj))
    assert "intf slot" not in plain and "IGreeter" not in plain and "vslot" in plain


def test_interface_type_from_finalize(proj):
    ctx, st, bid, pe, tab, imt = proj
    ti = st.db.execute("SELECT name FROM dl_method WHERE binary_id=? AND kind='interface-table'", (bid,)).fetchone()[0]
    typeinfo = delphi.parse_intf_table(ti).typeinfo
    text = ("void FUN_00401000(void)\n{\n  vmt_c_adc_0(local_8,1,&local_10);\n  vmt_c_adc_0(local_c,1,&local_10);\n"
            f"  System.@FinalizeArray/*0x00408c20*/((int *)&local_c,&DAT_{typeinfo:08x},2);\n}}\n")
    out = annotate(text, _cls(proj))
    assert out.count("/*IGreeter.Greet -> TBase.Greet*/") == 2                        # local_c and the next local
    assert intflabel.interface_vars(text, {typeinfo: "IGreeter"}, 4) == {"local_c": "IGreeter", "local_8": "IGreeter"}


def test_two_interfaces_list_candidates(tmp_path):
    pe = Pe(4)
    pe.klass("TObject", None, "System", 8, virtuals=("Dtor",))
    pe.klass("TBase", "TObject", "vc", 16, published=("Greet",), virtuals=("Dtor",))
    pe.klass("TOther", "TObject", "vc", 16, published=("Run",), virtuals=("Dtor",))
    c = [pe.stub(f"c{i}") for i in range(3)]
    add_interface(pe, "TBase", GUID, "IGreeter", [thunk(pe, "jmp", x) for x in c] + [thunk(pe, "jmp", pe.code["TBase.Greet"])], 8)
    add_interface(pe, "TOther", GUID2, "IRunner", [thunk(pe, "jmp", x) for x in c] + [thunk(pe, "jmp", pe.code["TOther.Run"])], 8)
    pe.write(tmp_path / "a.exe")
    index, types = _index_of(tmp_path)
    assert index["IGreeter"][3] == ("Greet", ["TBase.Greet"]) and index["IRunner"][3] == ("Run", ["TOther.Run"])
    assert len(types) == 2


def _index_of(tmp_path):
    from types import SimpleNamespace
    from airlock.server import classintf
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "cd" * 32
    (art / sha).write_bytes((tmp_path / "a.exe").read_bytes())
    bid = st.upsert_binary(sha, "vc.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="delphi", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert delphi.ensure(st, st.get_binary_by_id(bid), art / sha)
    cls = DbClasses(st, st.get_binary_by_id(bid), 0x401000)
    text = "void f(int *p)\n{\n  System.@IntfAddRef((int *)p);\n  vmt_c_adc_0(p,1);\n}\n"
    out = annotate(text, cls)
    assert "/*intf slot 3: IGreeter.Greet | IRunner.Run*/" in out                     # two candidates: no false certainty
    return classintf.index(SimpleNamespace(store=st, psize=4, binary=SimpleNamespace(id=bid, toolchain="delphi")))


def test_image_reads_without_interface_table(tmp_path):
    pe = Pe(4)
    pe.klass("TObject", None, "System", 8, virtuals=("Dtor",))
    pe.write(tmp_path / "a.exe")
    img = Image.from_pe(tmp_path / "a.exe")
    assert not [m for c in delphi.parse_classes(img) for m in c.methods if m.kind in delphi.INTF_KINDS]
