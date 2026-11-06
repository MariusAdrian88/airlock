"""Free Pascal (FPC / Lazarus) programs: detection, VMT / RTTI classes, forms, tool output.

Synthetic 32-bit and 64-bit PEs built on the Delphi test writer (``test_delphi.Pe``). The FPC layout is
written from the RTL's own declarations (``objpash.inc``, ``typinfo.pp``) and was compared with programs
built by FPC 3.2.2 (i386-win32 and x86_64-win64). All names are invented. No Ghidra."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from airlock import projects
from airlock.server import delphi
from airlock.server.cpp import Image
from airlock.server.tools import delphi as dtools
from test_delphi import TEXT_VA, Pe, _ss, comp, dfm, prop
from test_tools import make_ctx

MARKER = b"FPC 3.2.2 [2021/05/15] for i386 - Win32\0"
START = delphi.FPC_METHOD_START


class FpcPe(Pe):
    """A synthetic FPC binary. A class reference points at the start of the VMT: ``size, -size, parent,
    ^className, dyn, method, field, typeInfo, init, auto, intf, msgStr``, then the virtual methods."""

    def __init__(self, psize: int, marker: bool = True) -> None:
        super().__init__(psize)
        if marker:
            self.put(self.alloc(len(MARKER), 1), MARKER)
        self.late: list[tuple[int, str]] = []

    def fclass(self, name: str, parent: str | None, unit: str, size: int = 16, published: tuple[str, ...] = (),
               virtuals: int = 0, fields: tuple[tuple[str, int, str], ...] = (), props: tuple = (),
               via_cell: bool = False, typeinfo: bool = True, messages: tuple[int, ...] = (),
               strmsgs: tuple[str, ...] = (), interfaces: tuple[tuple[str, int, int], ...] = (),
               managed: tuple[tuple[int, int], ...] = (), intf_rtti: dict | None = None,
               intf_thunks: dict | None = None) -> int:
        """``props``: ``(name, getter, setter)``, an accessor is ``("code", method)``, ``("virt", slot)`` (the slot
        counts from the first virtual method), ``("field", offset)`` or None. ``intf_rtti``: {GUID text: (interface
        name, method names)}, writes the interface type info with its method table and thunk slots from 3 on;
        ``intf_thunks``: {GUID text: (class method names)}, thunk slots without type info."""
        ps = self.ps
        vmt = self.alloc((START + virtuals + 1) * ps, 16)
        self.vmts[name] = vmt
        words = [0] * START
        words[0], words[1] = size, (-size) & ((1 << (8 * ps)) - 1)
        words[3] = self.cstring(name)
        if typeinfo:
            procs = {"code": 1, "virt": 2, "field": 0}

            def acc(spec) -> tuple[int, int]:
                if spec is None:
                    return 0, 0
                if spec[0] == "code":
                    return self.code.get(f"{name}.{spec[1]}") or self.stub(f"{name}.{spec[1]}"), 1
                if spec[0] == "virt":
                    return (START + spec[1]) * ps, 2
                return spec[1], 0

            plist = b""
            for pname, g, s in props:
                (gv, gm), (sv, sm) = acc(g), acc(s)
                plist += (self.p(0) + self.p(gv) + self.p(sv) + self.p(0) + struct.pack("<iih", 0, 0, 0)
                          + bytes([gm | (sm << 2) | 0x30]) + _ss(pname))
            blob = (b"\x0f" + _ss(name) + self.p(vmt) + self.p(0) + struct.pack("<h", len(props)) + _ss(unit)
                    + struct.pack("<H", len(props)) + plist)
            ti = self.alloc(len(blob), 1)
            self.put(ti, blob)
            words[7] = ti
        if published:       # u32 count, then packed {^name, code}
            ents = b"".join(self.p(self.cstring(m)) + self.p(self.stub(f"{name}.{m}")) for m in published)
            tab = self.alloc(4 + len(ents), 4)
            self.put(tab, struct.pack("<I", len(published)) + ents)
            words[5] = tab
        if fields:          # u16 count, ptr classTab, {offset, u16 type index (1 based), name}
            ctab = self.alloc(2 + ps * len(fields), 2)
            body = b"".join(self.p(off) + struct.pack("<H", i + 1) + _ss(fn) for i, (fn, off, _t) in enumerate(fields))
            tab = self.alloc(2 + ps + len(body), 2)
            self.put(tab, struct.pack("<H", len(fields)) + self.p(ctab) + body)
            self.put(ctab, struct.pack("<H", len(fields)))
            for i, (_fn, _off, ft) in enumerate(fields):
                self.late.append((ctab + 2 + i * ps, ft))
            words[6] = tab
        if messages:        # dynamic table: ptr-wide count, then {u32 id; ptr code} entries of two words
            tab = self.alloc(ps + 2 * ps * len(messages), ps)
            body = b"".join(struct.pack("<I", mid).ljust(ps, b"\0") + self.p(self.stub(f"{name}.msg{mid:x}"))
                            for mid in messages)
            self.put(tab, struct.pack("<I", len(messages)).ljust(ps, b"\0") + body)
            words[4] = tab
        if strmsgs:         # count, then {^name, code}
            tab = self.alloc(ps + 2 * ps * len(strmsgs), ps)
            body = b"".join(self.p(self.cstring(m)) + self.p(self.stub(f"{name}.str{m}")) for m in strmsgs)
            self.put(tab, struct.pack("<I", len(strmsgs)).ljust(ps, b"\0") + body)
            words[11] = tab
        if interfaces:      # sizeuint count, then {^guid, vtable, IOffset, ^^ShortString, u32 IType (+pad)}
            ents = b""
            for gtext, nm, off in interfaces:
                gcell = self.alloc(16, 4)
                d1, d2, d3 = (int(x, 16) for x in (gtext[1:9], gtext[10:14], gtext[15:19]))
                tail = bytes.fromhex(gtext[20:24] + gtext[25:37])
                self.put(gcell, struct.pack("<IHH", d1, d2, d3) + tail)
                gref = self.alloc(ps)
                self.put(gref, self.p(gcell))
                sstr = self.cstring(gtext)
                sref = self.alloc(ps)
                self.put(sref, self.p(sstr))
                vt = self.alloc(ps * nm)
                impl: dict[int, int] = {}
                if gtext in (intf_rtti or {}):
                    iname, mnames = intf_rtti[gtext]
                    nm = 3 + len(mnames)
                    vt = self.alloc(ps * nm)
                    names = [self.cstring(m) for m in mnames]
                    ent = b"".join(self.p(0) + bytes([0, 0]) + struct.pack("<H", 0) + self.p(0) + self.p(n)
                                   for n in names)
                    blob = (bytes([14]) + _ss(iname) + self.p(0) + bytes([1]) + self.get_guid(gtext) + _ss("unit1")
                            + struct.pack("<HHH", 0, len(mnames), len(mnames)) + ent)
                    self.put(self.alloc(len(blob), 1), blob)
                    impl = {3 + i: self.stub(f"{name}.impl{3 + i}") for i in range(len(mnames))}
                for i, mname in enumerate((intf_thunks or {}).get(gtext, ())):
                    impl[3 + i] = self.code.get(f"{name}.{mname}") or self.stub(f"{name}.{mname}")
                self.put(vt, b"".join(self.p(self.thunk(f"{name}.{gtext}.{k}", impl[k]) if k in impl
                                             else self.stub(f"{name}.{gtext}.{k}")) for k in range(nm)))
                ents += self.p(gref) + self.p(vt) + self.p(off) + self.p(sref) + struct.pack("<I", 0).ljust(ps, b"\0")
            tab = self.alloc(ps + len(ents), ps)
            self.put(tab, self.p(len(interfaces)) + ents)
            words[10] = tab
        if managed:         # kind, name, packed {term ptr, i32 size, 2 ptrs, i32 count}, {^^typeinfo, offset}
            ents = b""
            for off, kind in managed:
                ti = self.alloc(2, 1)
                self.put(ti, bytes([kind, 0]))
                cell = self.alloc(ps)
                self.put(cell, self.p(ti))
                ents += self.p(cell) + self.p(off)
            blob = (b"\x0f" + _ss(name) + self.p(0) + struct.pack("<i", size) + self.p(0) + self.p(0)
                    + struct.pack("<i", len(managed)) + ents)
            ta = self.alloc(len(blob), 1)
            self.put(ta, blob)
            words[8] = ta
        if parent:
            if via_cell:
                cell = self.alloc(ps)
                self.late.append((cell, parent))
                words[2] = cell
            else:
                self.late.append((vmt + 2 * ps, parent))
        self.put(vmt, b"".join(self.p(w) for w in words)
                 + b"".join(self.p(self.stub(f"{name}.v{i}")) for i in range(virtuals)))
        return vmt

    @staticmethod
    def get_guid(gtext: str) -> bytes:
        d1, d2, d3 = (int(x, 16) for x in (gtext[1:9], gtext[10:14], gtext[15:19]))
        return struct.pack("<IHH", d1, d2, d3) + bytes.fromhex(gtext[20:24] + gtext[25:37])

    def thunk(self, name: str, target: int) -> int:
        """``sub eax, 0x24`` (``sub rcx, 0x24``), then ``jmp target``: what FPC puts in an interface vtable."""
        va = self.base + TEXT_VA + self.tpos
        head = bytes([0x83, 0xE8, 0x24]) if self.ps == 4 else bytes([0x48, 0x83, 0xE9, 0x24])
        code = head + bytes([0xE9]) + struct.pack("<i", target - (va + len(head) + 5))
        self.text[self.tpos:self.tpos + len(code)] = code
        self.tpos += 16
        self.code[name] = va
        return va

    def finish(self) -> None:
        for at, cls in self.late:
            self.put(at, self.p(self.vmts.get(cls, 0)))
        super().finish()


def build(path: Path, psize: int) -> FpcPe:
    pe = FpcPe(psize)
    pe.fclass("TObject", None, "System", psize, virtuals=2)
    pe.fclass("TBase", "TObject", "BaseUnit", 3 * psize, published=("Ping",), virtuals=3,
              props=(("Size", ("code", "GetSize"), ("virt", 2)), ("Raw", ("field", 8), None)))
    pe.fclass("TMainForm", "TBase", "MainUnit", 8 * psize, via_cell=True, virtuals=4,
              published=("Button1Click", "FormCreate"), fields=(("Button1", 16, "TBase"), ("Odd", 24, "")),
              props=(("Title", ("code", "GetTitle"), ("code", "SetTitle")),))
    pe.fclass("TNoInfo", "TObject", "", 2 * psize, typeinfo=False)
    main = dfm(comp("TMainForm", "MainForm", prop("Caption", "str", "Demo") + prop("OnCreate", "ident", "FormCreate"),
                    (comp("TButton", "Button1", prop("Caption", "str", "Go") + prop("OnClick", "ident", "Button1Click")),)))
    pe.res[(10, "TMAINFORM", 0x409)] = main
    pe.write(path)
    return pe


@pytest.mark.parametrize("psize", [4, 8])
def test_fpc_classes(tmp_path, psize):
    pe = build(tmp_path / "a.exe", psize)
    classes, forms = delphi.parse_file(tmp_path / "a.exe")
    by = {c.name: c for c in classes}
    assert sorted(by) == ["TBase", "TMainForm", "TNoInfo", "TObject"]
    assert [c.vmt for c in classes] == sorted(c.vmt for c in classes)
    main, base = by["TMainForm"], by["TBase"]
    assert (base.parent, base.unit, base.size) == ("TObject", "BaseUnit", 3 * psize)
    assert (main.parent, main.unit, main.vmt) == ("TBase", "MainUnit", pe.vmts["TMainForm"])   # parent through a cell
    assert by["TObject"].parent == "" and by["TNoInfo"].unit == "" and by["TNoInfo"].parent == "TObject"
    assert [(m.name, m.addr) for m in main.methods if m.kind == "published"] == [
        ("Button1Click", pe.code["TMainForm.Button1Click"]), ("FormCreate", pe.code["TMainForm.FormCreate"])]
    assert [(f.name, f.offset, f.type) for f in main.fields] == [("Button1", 16, "TBase"), ("Odd", 24, "")]
    assert main.nvirtual == 4 and base.nvirtual == 3
    virt = [m for m in main.methods if m.kind == "virtual"]
    assert [m.slot for m in virt] == [0, 1, 2, 3] and virt[0].addr == pe.code["TMainForm.v0"]
    props = {(m.kind, m.name): (m.addr, m.slot) for m in base.methods if m.kind.startswith("prop-")}
    assert props == {("prop-get", "Size"): (pe.code["TBase.GetSize"], -1),
                     ("prop-set", "Size"): (pe.code["TBase.v2"], 2)}         # a field accessor has no method
    assert {(m.kind, m.name) for m in main.methods if m.kind.startswith("prop-")} == {
        ("prop-get", "Title"), ("prop-set", "Title")}


@pytest.mark.parametrize("psize", [4, 8])
def test_fpc_form_and_events(tmp_path, psize):
    pe = build(tmp_path / "a.exe", psize)
    _classes, forms = delphi.parse_file(tmp_path / "a.exe")
    assert [f.root.cls for f in forms] == ["TMainForm"]
    ev = {e.prop: e.addr for e in forms[0].events}
    assert ev == {"OnCreate": pe.code["TMainForm.FormCreate"], "OnClick": pe.code["TMainForm.Button1Click"]}


def test_delphi_parser_ignores_fpc_vmts_and_back(tmp_path):
    build(tmp_path / "a.exe", 4)
    img = Image.from_pe(tmp_path / "a.exe")
    assert delphi._parse_delphi_classes(img) == []
    assert delphi.has_fpc_marker(img)
    from test_delphi import build as build_delphi
    build_delphi(tmp_path / "d.exe", 4)
    dimg = Image.from_pe(tmp_path / "d.exe")
    assert not delphi.has_fpc_marker(dimg)
    assert delphi.parse_fpc_classes(dimg) == []                 # no size / -size pair of a Delphi VMT passes


def test_fpc_without_marker_still_parses(tmp_path):
    pe = FpcPe(4, marker=False)
    pe.fclass("TObject", None, "System", 4)
    pe.fclass("TFoo", "TObject", "FooUnit", 8, published=("Bar",))
    pe.write(tmp_path / "a.exe")
    classes, _f = delphi.parse_file(tmp_path / "a.exe")
    assert [c.name for c in classes] == ["TObject", "TFoo"]


def test_damaged_tables_give_no_crash(tmp_path):
    """A class whose name pointer points nowhere is dropped; the rest of the image still parses."""
    pe = FpcPe(4)
    pe.fclass("TObject", None, "System", 4)
    pe.fclass("TGood", "TObject", "G", 8, published=("One",))
    vmt = pe.vmts["TGood"]
    pe.write(tmp_path / "a.exe")
    raw = bytearray((tmp_path / "a.exe").read_bytes())
    # corrupt the class name pointer of TGood: the class is dropped, TObject stays
    off = 0x200 + 0x1000 + (vmt - pe.base - 0x3000) + 3 * 4
    raw[off:off + 4] = struct.pack("<I", 0xDEADBEEF)
    (tmp_path / "b.exe").write_bytes(bytes(raw))
    classes, _f = delphi.parse_file(tmp_path / "b.exe")
    assert [c.name for c in classes] == ["TObject"]


# ── detection ──────────────────────────────────────────────────────────────

def test_detect_fpc_console_program(tmp_path):
    build(tmp_path / "a.exe", 4)
    info = projects.detect(tmp_path / "a.exe")
    assert (info.toolchain, info.toolchain_ver) == ("fpc", "3.2.2")


def test_detect_fpc_wins_over_the_form_resource_and_other_programs_are_untouched(tmp_path):
    pe = Pe(4)
    pe.res[(10, "TF", 0x409)] = dfm(comp("TF", "F"))
    pe.write(tmp_path / "d.exe")
    info = projects.detect(tmp_path / "d.exe")
    assert (info.toolchain, info.toolchain_ver) == ("delphi", None)
    assert projects.fpc_version(tmp_path / "d.exe") is None


@pytest.mark.parametrize("data,want", [
    (b"..FPC 3.2.2 [2021/05/15] for i386 - Win32..", "3.2.2"),
    (b"FPC 3.3.1-1234 [2023/01/01] for x86_64 - Win64", "3.3.1"),
    (b"FPC 3.2 [2021/05/15] for i386", None),
    (b"not FPC at all", None),
    (b"", None),
])
def test_fpc_version_string(tmp_path, data, want):
    f = tmp_path / "x.bin"
    f.write_bytes(data)
    assert projects.fpc_version(f) == want


def test_classify_fpc_before_form_resource_and_after_dotnet():
    assert projects.classify_toolchain(["KERNEL32.dll"], {"TPF0"}, False, False, True) == "fpc"
    assert projects.classify_toolchain([], set(), True, False, True) == "dotnet"
    assert projects.classify_toolchain(["KERNEL32.dll"], {"TPF0"}, False, False) == "delphi"


# ── tools ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fproj(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "ce" * 32
    pe = build(art / sha, 4)
    bid = st.upsert_binary(sha, "fp.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="fpc", toolchain_ver="3.2.2", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert delphi.ensure(st, st.get_binary_by_id(bid), art / sha)
    return ctx, st, bid, pe


def test_fpc_tools(fproj):
    ctx, st, bid, pe = fproj
    out = dtools.delphi_classes(ctx, query="mainform").splitlines()
    assert len(out) == 1 and out[0].startswith("TMainForm : TBase unit MainUnit vmt 0x")
    assert "published 2 virtual 4 fields 2" in out[0]
    assert dtools.delphi_forms(ctx).startswith("TMainForm MainForm")
    a = pe.code["TMainForm.Button1Click"]
    assert f"  Button1.OnClick -> TMainForm.Button1Click 0x{a:08x} (no function)" in \
        dtools.delphi_events(ctx, form="TMainForm").splitlines()


def test_fpc_hints_for_published_method(fproj):
    ctx, st, bid, pe = fproj
    assert "TMainForm.Button1Click (published)" in delphi.hints_for(st, bid, pe.code["TMainForm.Button1Click"])


def test_fpc_without_classes_says_so(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "cf" * 32
    pe = FpcPe(4)
    pe.write(art / sha)
    bid = st.upsert_binary(sha, "bare.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="fpc", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert dtools.delphi_classes(ctx).startswith("no Free Pascal classes: no VMT found")
    assert dtools.delphi_forms(ctx).startswith("no forms: the binary has no TPF0 form resources")


def test_lcl_and_fpc_rtl_units_count_as_runtime():
    assert all(delphi.runtime_unit(u) for u in ("System", "ObjPas", "LCLType", "Interfaces", "Forms", "StdCtrls"))
    assert not delphi.runtime_unit("MainForm")


@pytest.mark.parametrize("psize", [4, 8])
def test_fpc_message_interface_and_init_tables(tmp_path, psize):
    pe = FpcPe(psize)
    pe.fclass("TObject", None, "System", psize, virtuals=13)
    pe.fclass("TBase", "TObject", "BaseUnit", 6 * psize, virtuals=14, messages=(0x0F, 0x400),
              strmsgs=("hello",), managed=((psize, 9), (2 * psize, 14)),
              interfaces=(("{B4F1A2C3-1111-2222-3333-444455556666}", 5, 3 * psize),
                          ("{00000000-0000-0000-C000-000000000046}", 3, 4 * psize)),
              fields=(("FName", psize, ""),))
    pe.write(tmp_path / "a.exe")
    classes, _forms = delphi.parse_file(tmp_path / "a.exe", None, {"{B4F1A2C3-1111-2222-3333-444455556666}": "IGreeter"})
    base = {c.name: c for c in classes}["TBase"]
    msgs = [(m.kind, m.slot, m.name, m.addr) for m in base.methods if m.kind.startswith("message")]
    assert msgs == [("message", 0x0F, "WM_PAINT", pe.code["TBase.msgf"]),
                    ("message", 0x400, "WM_USER+0", pe.code["TBase.msg400"]),
                    ("message-str", 0, "hello", pe.code["TBase.strhello"])]
    intf = [(m.slot, m.name) for m in base.methods if m.kind == "interface"]
    assert intf[:3] == [(0, "IGreeter.QueryInterface"), (1, "IGreeter._AddRef"), (2, "IGreeter._Release")]
    assert intf[3:5] == [(3, "IGreeter.#3"), (4, "IGreeter.#4")] and len(intf) == 8
    assert intf[5][1] == "IUnknown.QueryInterface"
    fields = [(f.name, f.offset, f.type) for f in base.fields]
    assert fields == [("FName", psize, ""), ("", 2 * psize, "interface"), ("IGreeter", 3 * psize, "interface"),
                      ("IUnknown", 4 * psize, "interface")]            # the managed AnsiString at psize is a published field


@pytest.mark.parametrize("psize", [4, 8])
def test_fpc_interface_method_names(tmp_path, psize):
    g1, g2, g3 = ("{B4F1A2C3-1111-2222-3333-444455556666}", "{AABBCCDD-0000-1111-2222-333344445555}",
                  "{11111111-2222-3333-4444-555566667777}")
    pe = FpcPe(psize)
    pe.fclass("TObject", None, "System", psize, virtuals=13)
    pe.fclass("TBase", "TObject", "BaseUnit", 6 * psize, virtuals=14, published=("Ping",),
              interfaces=((g1, 0, 3 * psize), (g2, 4, 4 * psize), (g3, 5, 5 * psize)),
              intf_rtti={g1: ("IGreeter", ("Greet", "Count"))}, intf_thunks={g2: ("Ping",)})
    pe.write(tmp_path / "a.exe")
    classes, _forms = delphi.parse_file(tmp_path / "a.exe", None, {g2: "IPlain"})
    base = {c.name: c for c in classes}["TBase"]
    names = [(m.slot, m.name) for m in base.methods if m.kind == "interface"]
    assert [n for _s, n in names[:5]] == [f"{g1}.QueryInterface", f"{g1}._AddRef", f"{g1}._Release",
                                          f"{g1}.Greet", f"{g1}.Count"]       # type info method table
    assert names[5:9] == [(0, "IPlain.QueryInterface"), (1, "IPlain._AddRef"), (2, "IPlain._Release"),
                          (3, "IPlain.Ping")]                                # thunk jumps to a published method
    assert [n for _s, n in names[9:]] == [f"{g3}.{x}" for x in ("QueryInterface", "_AddRef", "_Release", "#3", "#4")]
    assert pe.code[f"TBase.{g1}.3"] != pe.code["TBase.impl3"]                # the slot is the thunk, not the target


@pytest.mark.parametrize("psize", [4, 8])
def test_fpc_virtual_slot_names(tmp_path, psize):
    pe = FpcPe(psize)
    pe.fclass("TObject", None, "System", psize, virtuals=13)
    pe.fclass("TComp", "TObject", "Classes", 2 * psize, virtuals=15)
    pe.fclass("TWin", "TComp", "Controls", 3 * psize, virtuals=16)
    pe.write(tmp_path / "a.exe")
    img = Image.from_pe(tmp_path / "a.exe")
    plain = {c.name: c for c in delphi.parse_fpc_classes(img)}
    # no class shares code with its parent here: every slot is named (TObject from the built-in list)
    assert [m.name for m in plain["TObject"].methods if m.kind == "virtual"] == list(delphi.FPC_TOBJECT_VSLOTS)
    assert [m.name for m in plain["TComp"].methods if m.kind == "virtual"][:2] == ["Destroy", "NewInstance"]
    assert plain["TComp"].methods[13].name == "" and plain["TWin"].methods[15].name == ""     # unknown slots
    named = {c.name: c for c in delphi.parse_fpc_classes(img, {"TComp": {13: "Loaded", 14: "Notification"},
                                                                "TWin": {15: "PaintWindow"}})}
    assert [m.name for m in named["TWin"].methods if m.kind == "virtual"][13:] == ["Loaded", "Notification", "PaintWindow"]
    assert named["TComp"].methods[14].name == "Notification"


def test_fpc_hints_for_tables(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    pe = FpcPe(4)
    pe.fclass("TObject", None, "System", 4, virtuals=13)
    pe.fclass("TBase", "TObject", "BaseUnit", 24, virtuals=14, messages=(0x0F,), strmsgs=("hello",),
              interfaces=(("{B4F1A2C3-1111-2222-3333-444455556666}", 4, 12),))
    sha = "cf" * 32
    pe.write(art / sha)
    bid = st.upsert_binary(sha, "fp.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="fpc", toolchain_ver="3.2.2", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert delphi.ensure(st, st.get_binary_by_id(bid), art / sha)
    assert "message handler WM_PAINT (0xf) of TBase" in delphi.hints_for(st, bid, pe.code["TBase.msgf"])
    assert "message handler 'hello' of TBase" in delphi.hints_for(st, bid, pe.code["TBase.strhello"])
    got = delphi.hints_for(st, bid, pe.code["TBase.{B4F1A2C3-1111-2222-3333-444455556666}.3"])
    assert "{B4F1A2C3-1111-2222-3333-444455556666}.#3 (interface slot 3) of TBase" in got
    assert "TObject::vslot 0 (Destroy)" in delphi.hints_for(st, bid, pe.code["TObject.v0"])
