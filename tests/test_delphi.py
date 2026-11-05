"""M6: Delphi VMTs, published methods and DFM forms, joined form -> event -> handler.

Synthetic 32-bit and 64-bit PEs: .text with code stubs, .data with VMTs (published method table, field
table, type info) and .rsrc with TPF0 RCDATA forms. All names are invented. No Ghidra."""

from __future__ import annotations

import math
import struct
from pathlib import Path

import pytest

from airlock.index.migrations import MIGRATIONS
from airlock.index.store import SCHEMA_VERSION
from airlock.server import clusters, delphi, features as fx, fnfix
from airlock.server.tools import delphi as dtools
from test_resources import rsrc_blob
from test_tools import make_ctx

# ── DFM encoder ────────────────────────────────────────────────────────────


def _ss(s: str) -> bytes:
    b = s.encode("latin-1")
    return bytes([len(b)]) + b


def _ext(x: float) -> bytes:
    if x == 0:
        return b"\0" * 10
    m, e = math.frexp(abs(x))                 # x = m * 2**e, 0.5 <= m < 1
    mant = int(m * 2**64)
    sign = 0x8000 if x < 0 else 0
    return struct.pack("<QH", mant, sign | (e - 1 + 16383))


def val(kind: str, v=None) -> bytes:
    if kind == "int":
        if -128 <= v < 128:
            return b"\x02" + struct.pack("<b", v)
        if -32768 <= v < 32768:
            return b"\x03" + struct.pack("<h", v)
        return b"\x04" + struct.pack("<i", v)
    if kind == "int64":
        return b"\x13" + struct.pack("<q", v)
    if kind == "float":
        return b"\x05" + _ext(v)
    if kind == "single":
        return b"\x0f" + struct.pack("<f", v)
    if kind == "currency":
        return b"\x10" + struct.pack("<q", int(v * 10000))
    if kind == "date":
        return b"\x11" + struct.pack("<d", v)
    if kind == "str":
        return b"\x06" + _ss(v)
    if kind == "lstr":
        return b"\x0c" + struct.pack("<I", len(v.encode("cp1252"))) + v.encode("cp1252")
    if kind == "wstr":
        return b"\x12" + struct.pack("<I", len(v)) + v.encode("utf-16-le")
    if kind == "utf8":
        raw = v.encode("utf-8")
        return b"\x14" + struct.pack("<I", len(raw)) + raw
    if kind == "ident":
        return b"\x07" + _ss(v)
    if kind == "bool":
        return b"\x09" if v else b"\x08"
    if kind == "nil":
        return b"\x0d"
    if kind == "null":
        return b"\x00"
    if kind == "binary":
        return b"\x0a" + struct.pack("<I", len(v)) + v
    if kind == "set":
        return b"\x0b" + b"".join(_ss(x) for x in v) + b"\x00"
    if kind == "list":
        return b"\x01" + b"".join(v) + b"\x00"
    if kind == "coll":                                  # items: list of (index or None, props bytes)
        out = b"\x0b"[:0] + b"\x0e"
        for idx, props in v:
            out += b"\x01" + (val("int", idx) if idx is not None else b"") + props + b"\x00"
        return out + b"\x00"
    raise ValueError(kind)


def prop(name: str, kind: str, v=None) -> bytes:
    return _ss(name) + val(kind, v)


def comp(cls: str, name: str, props: bytes = b"", children: tuple[bytes, ...] = (), flags: int = 0,
         pos: int | None = None) -> bytes:
    head = b""
    if flags or pos is not None:
        head = bytes([0xF0 | flags | (2 if pos is not None else 0)])
        if pos is not None:
            head += val("int", pos)
    return head + _ss(cls) + _ss(name) + props + b"\x00" + b"".join(children) + b"\x00"


def dfm(root: bytes) -> bytes:
    return b"TPF0" + root


# ── PE writer ──────────────────────────────────────────────────────────────

TEXT_VA, DATA_VA, RSRC_VA = 0x1000, 0x3000, 0x8000


class Pe:
    """A synthetic Delphi binary: ``psize`` 4 or 8; ``slots`` = pointer slots before the class reference."""

    def __init__(self, psize: int, slots: int | None = None) -> None:
        self.ps = psize
        self.slots = slots or (22 if psize == 4 else 25)
        self.base = 0x400000
        self.text = bytearray(0x1000)
        self.data = bytearray(0x4000)
        self.tpos = 0
        self.dpos = 0
        self.res: dict = {}
        self.vmts: dict[str, int] = {}
        self.code: dict[str, int] = {}

    # allocation
    def stub(self, name: str) -> int:
        va = self.base + TEXT_VA + self.tpos
        self.text[self.tpos] = 0xC3
        self.tpos += 16
        self.code[name] = va
        return va

    def alloc(self, n: int, align: int = 0) -> int:
        align = align or self.ps
        self.dpos = (self.dpos + align - 1) // align * align
        va = self.base + DATA_VA + self.dpos
        self.dpos += n
        return va

    def put(self, va: int, raw: bytes) -> None:
        off = va - self.base - DATA_VA
        self.data[off:off + len(raw)] = raw

    def p(self, v: int) -> bytes:
        return struct.pack("<I" if self.ps == 4 else "<Q", v)

    def cstring(self, s: str) -> int:
        raw = _ss(s)
        va = self.alloc(len(raw), 1)
        self.put(va, raw)
        return va

    def klass(self, name: str, parent: str | None, unit: str, size: int = 16,
              published: tuple[str, ...] = (), virtuals: tuple[str, ...] = (),
              fields: tuple[tuple[str, int, str], ...] = ()) -> int:
        """A class: VMT with ``virtuals`` code slots, a published method table and a field table."""
        ps = self.ps
        lo = self.alloc(self.slots * ps + max(len(virtuals), 1) * ps + 8)
        vmt = lo + self.slots * ps
        self.vmts[name] = vmt
        words = [0] * self.slots
        words[0] = vmt
        words[8] = self.cstring(name)
        # type info: kind, name, classType, parentInfo, propCount, unit
        ti = self.alloc(2 + len(name) + 2 * ps + 2 + 1 + len(unit), 1)
        self.put(ti, b"\x07" + _ss(name) + self.p(vmt) + self.p(0) + struct.pack("<h", 0) + _ss(unit))
        words[4] = ti
        if published:
            ents = b"".join(struct.pack("<H", 2 + ps + 1 + len(m)) + self.p(self.stub(f"{name}.{m}")) + _ss(m)
                            for m in published)
            tab = self.alloc(2 + len(ents), 2)
            self.put(tab, struct.pack("<H", len(published)) + ents)
            words[6] = tab
        if fields:
            ctab = self.alloc(2 + ps * len(fields), 2)
            body = b""
            cells = []
            for i, (fname, off, ftype) in enumerate(fields):
                cell = self.alloc(ps)
                cells.append((cell, ftype))
                body += self.p(off) + struct.pack("<H", i) + _ss(fname)
            tab = self.alloc(2 + ps + len(body), 2)
            self.put(tab, struct.pack("<H", len(fields)) + self.p(ctab) + body)
            self.put(ctab, struct.pack("<H", len(fields)) + b"".join(self.p(c) for c, _t in cells))
            words[5] = tab
            self._cells = getattr(self, "_cells", []) + cells
        if parent:
            pcell = self.alloc(ps)
            self._parents = getattr(self, "_parents", []) + [(pcell, parent)]
            words[10] = pcell
        words[9] = size
        for i in range(11, self.slots):
            words[i] = self.stub(f"{name}.slot{i}")
        blob = b"".join(self.p(w) if i != 9 else struct.pack("<I", w).ljust(ps, b"\0")
                        for i, w in enumerate(words))
        self.put(lo, blob)
        self.put(vmt, b"".join(self.p(self.stub(f"{name}.v{i}_{v}")) for i, v in enumerate(virtuals)))
        return vmt

    def finish(self) -> None:
        for cell, parent in getattr(self, "_parents", []):
            self.put(cell, self.p(self.vmts[parent]))
        for cell, ftype in getattr(self, "_cells", []):
            self.put(cell, self.p(self.vmts.get(ftype, 0)))

    def write(self, path: Path) -> None:
        self.finish()
        plus = self.ps == 8
        rsrc = rsrc_blob(self.res, RSRC_VA)
        text, data = bytes(self.text), bytes(self.data)
        rsrc_raw = rsrc.ljust((len(rsrc) + 0x1FF) & ~0x1FF, b"\0")
        magic = 0x20B if plus else 0x10B
        opt = struct.pack("<HBBIII", magic, 0, 0, len(text), len(data) + len(rsrc), 0)
        opt += struct.pack("<II", TEXT_VA, TEXT_VA)                      # entry point, base of code
        if plus:
            opt += struct.pack("<Q", self.base)
        else:
            opt += struct.pack("<II", DATA_VA, self.base)
        opt += struct.pack("<II", 0x1000, 0x200)
        opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        opt += struct.pack("<IIII", 0, RSRC_VA + ((len(rsrc) + 0xFFF) & ~0xFFF), 0x200, 0)
        opt += struct.pack("<HH", 3, 0)
        opt += struct.pack("<QQQQ" if plus else "<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        opt += struct.pack("<II", 0, 16) + b"\0" * 16 + struct.pack("<II", RSRC_VA, len(rsrc)) + b"\0" * (13 * 8)
        coff = struct.pack("<HHIIIHH", 0x8664 if plus else 0x14C, 3, 0, 0, 0, len(opt), 0x2022 if plus else 0x2102)
        off = 0x200
        sects = b""
        for name, va, raw, ch, vsize in ((b".text", TEXT_VA, text, 0x60000020, len(text)),
                                         (b".data", DATA_VA, data, 0xC0000040, len(data)),
                                         (b".rsrc", RSRC_VA, rsrc_raw, 0x40000040, len(rsrc))):
            sects += struct.pack("<8sIIIIIIHHI", name, vsize, va, len(raw), off, 0, 0, 0, 0, ch)
            off += len(raw)
        hdr = (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + sects).ljust(0x200, b"\0")
        path.write_bytes(hdr + text + data + rsrc_raw)


MAIN_DFM = dfm(comp("TMainForm", "MainForm", prop("Caption", "str", "Demo") + prop("OnCreate", "ident", "FormCreate"), (
    comp("TButton", "Button1", prop("Caption", "str", "Run") + prop("OnClick", "ident", "Button1Click")),
    comp("TButton", "Button2", prop("Caption", "wstr", "Stop é") + prop("OnClick", "ident", "NoSuchHandler")),
    comp("TPanel", "Panel1", prop("Align", "ident", "alTop"), (
        comp("TCheckBox", "Check1", prop("Caption", "utf8", "Verbose") + prop("OnClick", "ident", "CheckClick")
             + prop("OnMouseDown", "ident", "BaseMouseDown"), (), 0, 7),
    )),
    comp("TMainMenu", "Menu1", b"", (
        comp("TMenuItem", "FileOpen1", prop("Caption", "str", "&Open") + prop("OnClick", "ident", "OpenClick")),
    )),
    comp("TFrame1", "Frame11", b"", (
        comp("TButton", "FrameBtn", prop("OnClick", "ident", "FrameBtnClick")),
    ), flags=4),
    comp("TStringGrid", "Grid", prop("Columns", "coll", [(0, prop("Title", "str", "A") + prop("OnClick", "ident", "GridCol"))])),
)))

CHILD_DFM = dfm(comp("TChildForm", "ChildForm", prop("OnShow", "ident", "BaseShow") + prop("OnClose", "ident", "ChildClose"),
                     (), flags=1))


def build(path: Path, psize: int, slots: int | None = None) -> Pe:
    pe = Pe(psize, slots)
    pe.klass("TObject", None, "System", 8, virtuals=("Dtor",))
    pe.klass("TComponent", "TObject", "System.Classes", 32, virtuals=("Dtor",))
    pe.klass("TBaseForm", "TComponent", "BaseUnit", 64, published=("BaseMouseDown", "BaseShow"), virtuals=("Init", "Done"))
    pe.klass("TMainForm", "TBaseForm", "MainUnit", 128, published=("FormCreate", "Button1Click", "CheckClick", "OpenClick",
                                                                  "GridCol"),
             virtuals=("Init", "Done", "Extra"), fields=(("Button1", 40, "TObject"), ("Check1", 48, "TComponent")))
    pe.klass("TFrame1", "TBaseForm", "FrameUnit", 80, published=("FrameBtnClick",))
    pe.klass("TChildForm", "TMainForm", "ChildUnit", 140, published=("ChildClose",))
    pe.res[(10, "TMAINFORM", 0x409)] = MAIN_DFM
    pe.res[(10, "TCHILDFORM", 0x409)] = CHILD_DFM
    pe.res[(10, "NOTADFM", 0x409)] = b"hello"
    pe.write(path)
    return pe


# ── parser tests ───────────────────────────────────────────────────────────

def test_dfm_value_types():
    raw = dfm(comp("TFoo", "Foo", b"".join([
        prop("A", "int", 5), prop("B", "int", -300), prop("C", "int", 70000), prop("D", "int64", 1 << 40),
        prop("E", "float", 3.5), prop("F", "single", 0.25), prop("G", "currency", 12.5), prop("H", "date", 1.5),
        prop("I", "str", "abc"), prop("J", "lstr", "café"), prop("K", "wstr", "中"), prop("L", "utf8", "é"),
        prop("M", "ident", "alClient"), prop("N", "bool", True), prop("O", "bool", False), prop("P", "nil"),
        prop("Q", "binary", b"\x01\x02"), prop("R", "set", ["a", "b"]),
        prop("S", "list", [val("int", 1), val("str", "x")]),
        prop("T", "coll", [(None, prop("Name", "str", "n1")), (3, prop("OnClick", "ident", "H1"))]),
    ]), (comp("TBar", "Bar", prop("Left", "int", 1), (comp("TBaz", "Baz"),)),)))
    root = delphi.parse_dfm(raw)
    p = {x.name: x for x in root.props}
    assert (p["A"].value, p["B"].value, p["C"].value, p["D"].value) == (5, -300, 70000, 1 << 40)
    assert p["E"].value == 3.5 and p["F"].value == 0.25 and p["G"].value == 12.5 and p["H"].value == 1.5
    assert (p["I"].value, p["J"].value, p["K"].value, p["L"].value) == ("abc", "café", "中", "é")
    assert p["M"].kind == "ident" and p["M"].value == "alClient"
    assert p["N"].value is True and p["O"].value is False and p["P"].kind == "nil"
    assert p["Q"].value == b"\x01\x02" and p["R"].value == ["a", "b"] and p["S"].value == [1, "x"]
    assert [[q.value for q in item] for item in p["T"].value] == [["n1"], ["H1"]]
    assert [c.name for c in root.children] == ["Bar"] and root.children[0].children[0].name == "Baz"
    assert [r[0] for r in delphi.walk(root)] == [0, 1, 2]


def test_dfm_flags_and_events():
    root = delphi.parse_dfm(MAIN_DFM)
    rows = delphi.walk(root)
    names = [c.name for _s, _p, _d, c in rows]
    assert names == ["MainForm", "Button1", "Button2", "Panel1", "Check1", "Menu1", "FileOpen1", "Frame11",
                     "FrameBtn", "Grid"]
    assert root.caption == "Demo" and rows[2][3].caption == "Stop é"
    assert rows[7][3].inline
    ev = {(e.prop, e.handler): e.owner for e in delphi.events_of(root)}
    assert ev[("OnCreate", "FormCreate")] == "TMainForm"
    assert ev[("OnClick", "Button1Click")] == "TMainForm"
    assert ev[("OnClick", "FrameBtnClick")] == "TFrame1"            # child of an inline frame
    assert ev[("Columns[0].OnClick", "GridCol")] == "TMainForm"      # collection item
    assert not any(e.handler == "alTop" for e in delphi.events_of(root))


def test_dfm_rejects_garbage():
    with pytest.raises(delphi.DfmError):
        delphi.parse_dfm(b"XXXX")
    with pytest.raises(delphi.DfmError):
        delphi.parse_dfm(MAIN_DFM[:40])


@pytest.mark.parametrize("psize,slots", [(4, None), (8, None), (4, 19), (8, 22)])
def test_vmt_and_join(tmp_path, psize, slots):
    pe = build(tmp_path / "app.exe", psize, slots)
    classes, forms = delphi.parse_file(tmp_path / "app.exe")
    by = {c.name: c for c in classes}
    assert set(by) == {"TObject", "TComponent", "TBaseForm", "TMainForm", "TFrame1", "TChildForm"}
    main = by["TMainForm"]
    assert main.vmt == pe.vmts["TMainForm"] and main.parent == "TBaseForm" and main.unit == "MainUnit"
    assert main.size == 128 and by["TObject"].parent == "" and by["TChildForm"].parent == "TMainForm"
    pub = {m.name: m.addr for m in main.methods if m.kind == "published"}
    assert pub == {n: pe.code[f"TMainForm.{n}"] for n in ("FormCreate", "Button1Click", "CheckClick", "OpenClick", "GridCol")}
    assert [m.addr for m in main.methods if m.kind == "virtual"] == [pe.code[f"TMainForm.v{i}_{n}"]
                                                                      for i, n in enumerate(("Init", "Done", "Extra"))]
    assert [(f.name, f.offset, f.type) for f in main.fields] == [("Button1", 40, "TObject"), ("Check1", 48, "TComponent")]
    assert by["TMainForm"].nvirtual == 3
    fm = {f.res_name: f for f in forms}
    assert set(fm) == {"TMAINFORM", "TCHILDFORM"}
    got = {(e.prop, e.handler): e.addr for e in fm["TMAINFORM"].events}
    assert got[("OnClick", "Button1Click")] == pe.code["TMainForm.Button1Click"]
    assert got[("OnCreate", "FormCreate")] == pe.code["TMainForm.FormCreate"]
    assert got[("OnClick", "NoSuchHandler")] is None
    assert got[("OnMouseDown", "BaseMouseDown")] == pe.code["TBaseForm.BaseMouseDown"]       # ancestor
    assert got[("OnClick", "FrameBtnClick")] == pe.code["TFrame1.FrameBtnClick"]             # inline frame class
    assert got[("Columns[0].OnClick", "GridCol")] == pe.code["TMainForm.GridCol"]
    child = {(e.prop, e.handler): e.addr for e in fm["TCHILDFORM"].events}
    assert child[("OnShow", "BaseShow")] == pe.code["TBaseForm.BaseShow"]
    assert child[("OnClose", "ChildClose")] == pe.code["TChildForm.ChildClose"]


def test_not_delphi_gives_no_classes(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"MZ" + b"\0" * 100)
    assert delphi.parse_file(p) is None


# ── store, tools, hints ────────────────────────────────────────────────────

@pytest.fixture
def proj(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "cd" * 32
    pe = build(art / sha, 4)
    bid = st.upsert_binary(sha, "app.exe", format="pe32", arch="x86", pointer_size=4,
                           image_base=0x400000, toolchain="delphi", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    b = st.get_binary_by_id(bid)
    assert delphi.ensure(st, b, art / sha)
    names = {"TMainForm.Button1Click": ("TMainForm", "Button1Click"), "TMainForm.FormCreate": (None, "FUN_a")}
    st.insert_functions(bid, [{"entry": pe.code[k], "name": n, "name_state": "auto", "namespace": ns, "size": 3}
                              for k, (ns, n) in names.items()])
    return ctx, st, bid, pe


def test_schema_and_ensure(proj):
    ctx, st, bid, pe = proj
    assert SCHEMA_VERSION >= 12 and 12 in MIGRATIONS
    b = st.get_binary_by_id(bid)
    assert not delphi.stale(st, bid) and not delphi.ensure(st, b, Path("nope"))
    st.set_meta(delphi.meta_key(bid), "0")
    assert delphi.stale(st, bid)
    assert delphi.ensure(st, b, ctx.indexer.paths("proj").artifacts / b.sha256)
    n = st.db.execute("SELECT COUNT(*) FROM dl_class WHERE binary_id=?", (bid,)).fetchone()[0]
    assert n == 6
    other = st.upsert_binary("ef" * 32, "m.dll", format="pe32", toolchain="msvc")
    assert not delphi.ensure(st, st.get_binary_by_id(other), Path("x"))      # other toolchains are skipped


def test_delphi_forms_tool(proj):
    ctx, st, bid, pe = proj
    out = dtools.delphi_forms(ctx).splitlines()
    assert any(ln.startswith("TMainForm MainForm") and 'components 10 events 8' in ln for ln in out)
    tree = dtools.delphi_forms(ctx, form="TMainForm").splitlines()
    assert tree[0].startswith('TMainForm MainForm "Demo" components 10')
    assert any(ln == '  Button1: TButton "Run" events 1' for ln in tree)
    assert any(ln == "    Check1: TCheckBox \"Verbose\" events 2" for ln in tree)
    assert "0x" not in "\n".join(tree)                                         # no addresses by default
    assert dtools.delphi_forms(ctx, form="mainform").startswith('TMainForm MainForm')
    assert dtools.delphi_forms(ctx, form="zzz").startswith("error not_found:")
    assert dtools.delphi_forms(ctx, form="Form").startswith("error ambiguous:")


def test_delphi_events_tool(proj):
    ctx, st, bid, pe = proj
    out = dtools.delphi_events(ctx, form="TMainForm").splitlines()
    a = pe.code["TMainForm.Button1Click"]
    assert out[0] == "TMainForm events 8"
    assert f"  Button1.OnClick -> TMainForm.Button1Click 0x{a:08x} TMainForm::Button1Click" in out
    assert f"  MainForm.OnCreate -> TMainForm.FormCreate 0x{pe.code['TMainForm.FormCreate']:08x} FUN_a" in out
    assert "  Button2.OnClick -> NoSuchHandler (not in the published methods)" in out
    comp_out = dtools.delphi_events(ctx, component="Button1").splitlines()
    assert comp_out == [f"TMainForm Button1.OnClick -> TMainForm.Button1Click 0x{a:08x} TMainForm::Button1Click"]
    assert dtools.delphi_events(ctx).startswith("error bad_args:")
    assert dtools.delphi_events(ctx, component="Nope").startswith("error not_found:")


def test_delphi_classes_tool(proj):
    ctx, st, bid, pe = proj
    out = dtools.delphi_classes(ctx, query="mainform").splitlines()
    assert len(out) == 1 and out[0].startswith("TMainForm : TBaseForm unit MainUnit vmt 0x")
    assert "published 5 virtual 3 fields 2" in out[0]
    assert len(dtools.delphi_classes(ctx).splitlines()) == 6
    assert dtools.delphi_classes(ctx, query="zzz").startswith("no Delphi class matches")


def test_not_delphi_binary_error(proj):
    ctx, st, bid, pe = proj
    other = st.upsert_binary("ef" * 32, "m.dll", format="pe32", arch="x86", pointer_size=4, toolchain="msvc",
                             analysis_profile="p")
    ctx.indexer.set_status(st, other, "ready")
    assert dtools.delphi_classes(ctx, binary="m.dll").startswith("error not_delphi:")
    assert len(dtools.delphi_classes(ctx).splitlines()) == 6        # without binary: Delphi binaries only


def test_hints_and_candidates(proj):
    ctx, st, bid, pe = proj
    a = pe.code["TMainForm.Button1Click"]
    hints = delphi.hints_for(st, bid, a)
    assert "TMainForm.Button1Click (published)" in hints
    assert 'handler OnClick of Button1 (TButton "Run") in form TMainForm' in hints
    v = delphi.hints_for(st, bid, pe.code["TMainForm.v2_Extra"])
    assert v == ["TMainForm::vslot 2"]
    # fnfix: the handler of Button1Click is a function; the others are candidates
    cands = set(fnfix.candidates(st, bid))
    assert pe.code["TMainForm.OpenClick"] in cands and a not in cands
    assert pe.code["TMainForm.v1_Done"] in cands


def test_ui_line_and_feature_seeds(proj):
    ctx, st, bid, pe = proj
    line = delphi.ui_line(st, bid)
    assert line.startswith("UI: 2 Delphi forms; events 10, mapped to handlers 9")
    seeds = delphi.feature_seeds(st, bid)
    kinds = {(k, ev) for _a, k, ev in seeds}
    assert ("ui-menu", 'TMainForm.FileOpen1 "&Open" OnClick') in kinds
    assert ("ui-dialog", 'TMainForm.Button1 "Run" OnClick') in kinds
    assert fx.FEATURES_VERSION >= 6


def test_runtime_recognition():
    assert clusters.runtime_family("@LStrAsg", None, "auto") == "Delphi"
    assert clusters.runtime_family("@HandleFinally", None, "auto") == "Delphi"
    assert clusters.runtime_family("@__security_check_cookie@4", None, "auto") != "Delphi"
    assert clusters.runtime_family("Button1Click", "TMainForm", "auto") is None
    assert clusters.runtime_family("Create", "System::Classes", "auto") == "Delphi"
    assert delphi.runtime_unit("System.Classes") and delphi.runtime_unit("Vcl.Forms")
    assert delphi.runtime_unit("SysUtils") and not delphi.runtime_unit("MainUnit")
    assert clusters.runtime_label(["Delphi", "Delphi", "CRT"]) == "runtime: Delphi"


def test_runtime_addrs(proj):
    ctx, st, bid, pe = proj
    rt = delphi.runtime_addrs(st, bid)
    assert pe.code["TComponent.v0_Dtor"] in rt                      # unit System.Classes
    assert pe.code["TMainForm.Button1Click"] not in rt             # unit MainUnit
    assert pe.code["TObject.v0_Dtor"] in rt                         # unit System
