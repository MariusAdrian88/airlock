"""MSVC RTTI, vtables and MFC message maps: synthetic byte images (32-bit and 64-bit), the store
rows, the name hints and the cpp tools. All names are invented."""

from __future__ import annotations

import struct

import pytest

from airlock.config.catalog import CATALOG
from airlock.index.migrations import MIGRATIONS
from airlock.index.store import SCHEMA_VERSION, Store
from airlock.server import cpp, roles
from airlock.server.tools import cpp as cpp_tools
from test_tools import fill, make_ctx

WM_COMMAND, WM_PAINT, WM_TIMER, WM_NOTIFY = 0x111, 0x0F, 0x113, 0x4E
UPDATE_UI = 0xFFFFFFFF


class Builder:
    """Builds a two-section image: .text (executable) and .rdata (data)."""

    def __init__(self, psize: int) -> None:
        self.ps = psize
        self.base = 0x400000 if psize == 4 else 0x140000000
        self.text_va = self.base + 0x1000
        self.rd_va = self.base + 0x3000
        self.text = bytearray()
        self.rd = bytearray()

    # -- primitives --
    def _alloc(self, buf: bytearray, va0: int, data: bytes, align: int = 8) -> int:
        while len(buf) % align:
            buf.append(0)
        va = va0 + len(buf)
        buf += data
        return va

    def code(self, data: bytes) -> int:
        return self._alloc(self.text, self.text_va, data, 16)

    def data(self, data: bytes, align: int = 8) -> int:
        return self._alloc(self.rd, self.rd_va, data, align)

    def ptr(self, v: int) -> bytes:
        return struct.pack("<I" if self.ps == 4 else "<Q", v)

    def ref(self, va: int) -> bytes:
        return struct.pack("<I", va if self.ps == 4 else va - self.base)

    # -- code --
    def getter(self, target: int) -> int:
        """mov eax, imm32; ret   /   lea rax, [rip+d]; ret"""
        va = self.text_va + (len(self.text) + 15) // 16 * 16
        if self.ps == 4:
            return self.code(b"\xb8" + struct.pack("<I", target) + b"\xc3")
        rel = target - (va + 7)
        return self.code(b"\x48\x8d\x05" + struct.pack("<i", rel) + b"\xc3")

    def jmp_to(self, target: int) -> int:
        va = self.text_va + (len(self.text) + 15) // 16 * 16
        return self.code(b"\xe9" + struct.pack("<i", target - (va + 5)))

    def stub(self) -> int:
        return self.code(b"\x90\x90\xc3")

    # -- RTTI --
    def td(self, mangled: str) -> int:
        return self.data(self.ptr(0x1234) + self.ptr(0) + mangled.encode() + b"\0")

    def chd(self, bases: list[tuple[int, int]]) -> int:
        """bases: [(td, numContainedBases)] for the class itself first."""
        bcds = [self.data(self.ref(td) + struct.pack("<I", n) + struct.pack("<iiiI", 0, -1, 0, 0x40))
                for td, n in bases]
        arr = self.data(b"".join(self.ref(b) for b in bcds), 4)
        return self.data(struct.pack("<III", 0, 0, len(bases)) + self.ref(arr))

    def col(self, td: int, chd: int, offset: int = 0) -> int:
        if self.ps == 4:
            return self.data(struct.pack("<III", 0, offset, 0) + self.ref(td) + self.ref(chd))
        va = self.rd_va + (len(self.rd) + 7) // 8 * 8
        return self.data(struct.pack("<III", 1, offset, 0) + self.ref(td) + self.ref(chd) + self.ref(va))

    def vtable(self, col: int | None, slots: list[int]) -> int:
        head = self.ptr(col) if col is not None else self.ptr(0)
        va = self.data(head + b"".join(self.ptr(s) for s in slots))
        return va + self.ps

    # -- MFC --
    def msgmap(self, entries: list[tuple], base: int = 0) -> int:
        """entries: (message, code, id, last_id, sig, handler)."""
        fmt = "<6I" if self.ps == 4 else "<4IQQ"
        raw = b"".join(struct.pack(fmt, *e) for e in entries) + bytes(cpp.entry_size(self.ps))
        ents = self.data(raw)
        return self.data(self.ptr(base) + self.ptr(ents))

    def image(self) -> cpp.Image:
        text = cpp.Section(self.text_va, bytes(self.text).ljust(0x1000, b"\xcc"), True, 0x1000)
        rd = cpp.Section(self.rd_va, bytes(self.rd).ljust(0x4000, b"\0"), False, 0x4000)
        return cpp.Image(self.ps, self.base, [text, rd])


def build(psize: int) -> tuple[Builder, dict]:
    """Base `Ns::CBase`, derived `CDerived : CBase` (own map), `CPlain : CBase` (inherits the slot),
    a non-RTTI class with a map, and a class with a DLL-style `jmp` thunk getter."""
    b = Builder(psize)
    h_open, h_close, h_upd, h_paint, h_tim = (b.stub() for _ in range(5))
    h_base = b.stub()
    virt = [b.stub() for _ in range(2)]
    base_map = b.msgmap([(WM_COMMAND, 0, 100, 100, 12, h_base)])
    der_map = b.msgmap([(WM_COMMAND, 0, 200, 200, 12, h_open),
                        (WM_COMMAND, 0, 201, 205, 12, h_close),
                        (WM_COMMAND, UPDATE_UI, 200, 200, 66, h_upd),
                        (WM_PAINT, 0, 0, 0, 19, h_paint),
                        (WM_TIMER, 0, 0, 0, 40, h_tim)], base=base_map)
    anon_map = b.msgmap([(WM_NOTIFY, 0xFFFFFFFE, 300, 300, 55, h_open)])
    thunk_map = b.msgmap([(WM_COMMAND, 0, 400, 400, 12, h_close)])
    g_base, g_der, g_anon, g_thunk_target = (b.getter(base_map), b.getter(der_map), b.getter(anon_map),
                                             b.getter(thunk_map))
    g_thunk = b.jmp_to(g_thunk_target)
    td_base, td_der, td_plain, td_thunk = (b.td(".?AVCBase@Ns@@"), b.td(".?AVCDerived@@"),
                                           b.td(".?AVCPlain@@"), b.td(".?AUSThunk@@"))
    chd_base = b.chd([(td_base, 0)])
    chd_der = b.chd([(td_der, 1), (td_base, 0)])
    chd_plain = b.chd([(td_plain, 1), (td_base, 0)])
    chd_thunk = b.chd([(td_thunk, 0)])
    col_base, col_der = b.col(td_base, chd_base), b.col(td_der, chd_der)
    col_plain, col_thunk = b.col(td_plain, chd_plain), b.col(td_thunk, chd_thunk)
    col_der2 = b.col(td_der, chd_der, offset=8)
    vt_base = b.vtable(col_base, [virt[0], virt[1], g_base])
    vt_der = b.vtable(col_der, [virt[0], h_open, g_der])
    vt_der2 = b.vtable(col_der2, [h_close])
    vt_plain = b.vtable(col_plain, [virt[0], virt[1], g_base])
    vt_thunk = b.vtable(col_thunk, [virt[1], g_thunk])
    vt_anon = b.vtable(None, [virt[0], g_anon])
    return b, dict(h_open=h_open, h_close=h_close, h_upd=h_upd, h_paint=h_paint, h_tim=h_tim, h_base=h_base,
                   virt=virt, base_map=base_map, der_map=der_map, anon_map=anon_map, thunk_map=thunk_map,
                   vt_base=vt_base, vt_der=vt_der, vt_der2=vt_der2, vt_plain=vt_plain, vt_thunk=vt_thunk,
                   vt_anon=vt_anon, td_base=td_base, td_der=td_der, col_base=col_base, col_der=col_der,
                   col_der2=col_der2)


@pytest.fixture(params=[4, 8], ids=["x86", "x64"])
def built(request):
    b, a = build(request.param)
    return b, a, b.image()


# ── names, labels ──────────────────────────────────────────────────────────

def test_demangle():
    assert cpp.demangle(".?AVCFoo@@") == "CFoo"
    assert cpp.demangle(".?AVInner@Outer@Ns@@") == "Ns::Outer::Inner"
    assert cpp.demangle(".?AUS@@") == "S"
    assert cpp.demangle("plain") == "plain"
    assert cpp.demangle(".?AVfoo@?A0x1234abcd@@") == "`anonymous namespace'::foo"


def test_message_labels():
    assert cpp.message_name(0x111) == "WM_COMMAND" and cpp.message_name(0x0F) == "WM_PAINT"
    assert cpp.message_name(0x113) == "WM_TIMER" and cpp.message_name(0x4E) == "WM_NOTIFY"
    assert cpp.message_name(0x401) == "WM_USER+1" and cpp.message_name(0x8002) == "WM_APP+2"
    assert cpp.message_name(0xC000) == "WM_REGISTERED" and cpp.message_name(0xE000) == "0xe000"
    assert cpp.entry_label(0x111, 0) == "WM_COMMAND"
    assert cpp.entry_label(0x111, 0xFFFFFFFF) == "UPDATE_COMMAND_UI"
    assert cpp.entry_label(0x111, 0x300) == "WM_COMMAND code 0x300"
    assert cpp.entry_label(0x4E, 0xFFFFFFFE) == "WM_NOTIFY NM_CLICK"
    assert cpp.entry_label(0x0F, 0) == "WM_PAINT"


# ── RTTI and vtables ───────────────────────────────────────────────────────

def test_parse_rtti_and_vtables(built):
    b, a, img = built
    classes = {(c.name, c.offset): c for c in cpp.parse_rtti(img)}
    assert set(classes) == {("Ns::CBase", 0), ("CDerived", 0), ("CDerived", 8), ("CPlain", 0), ("SThunk", 0)}
    c = classes[("CDerived", 0)]
    assert (c.td, c.col, c.vtable, c.bases) == (a["td_der"], a["col_der"], a["vt_der"], ["Ns::CBase"])
    assert classes[("CDerived", 8)].vtable == a["vt_der2"]
    assert classes[("Ns::CBase", 0)].bases == []
    assert classes[("CPlain", 0)].vtable == a["vt_plain"]
    assert cpp.vtable_slots(img, a["vt_base"]) == [a["virt"][0], a["virt"][1], img.ptr(a["vt_base"] + 2 * b.ps)]
    assert len(cpp.vtable_slots(img, a["vt_der2"])) == 1         # stops at the next COL pointer


def test_no_rtti_is_empty():
    b = Builder(4)
    b.stub()
    assert cpp.parse_rtti(b.image()) == []


def test_direct_bases_only():
    """A -> B -> C: the hierarchy array lists B and C for A, but only B is a direct base."""
    b = Builder(8)
    ta, tb, tc = b.td(".?AVA@@"), b.td(".?AVB@@"), b.td(".?AVC@@")
    chd = b.chd([(ta, 2), (tb, 1), (tc, 0)])
    col = b.col(ta, chd)
    b.vtable(col, [b.stub()])
    (c,) = cpp.parse_rtti(b.image())
    assert (c.name, c.bases) == ("A", ["B"])


# ── message maps ───────────────────────────────────────────────────────────

def test_returned_address_variants():
    b = Builder(4)
    tgt = b.data(b"\0" * 8)
    plain = b.getter(tgt)
    frame = b.code(b"\x55\x8b\xec\xb8" + struct.pack("<I", tgt) + b"\x5d\xc3")
    spill = b.code(b"\x55\x8b\xec\x51\x89\x4d\xfc\xb8" + struct.pack("<I", tgt) + b"\xc9\xc3")
    thunk = b.jmp_to(plain)
    call = b.code(b"\xe8" + struct.pack("<i", plain - (b.text_va + (len(b.text) + 15) // 16 * 16 + 5)) + b"\xc3")
    junk = b.code(b"\x8b\x01\xc3")
    img = b.image()
    for fn in (plain, frame, spill, thunk, call):
        assert cpp.returned_address(img, fn) == tgt
    assert cpp.returned_address(img, junk) is None


def test_returned_address_x64_call_stub():
    b = Builder(8)
    tgt = b.data(b"\0" * 8)
    inner = b.getter(tgt)
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    outer = b.code(b"\x48\x83\xec\x28\xe8" + struct.pack("<i", inner - (va + 9)) + b"\x48\x83\xc4\x28\xc3")
    assert cpp.returned_address(b.image(), outer) == tgt


def test_parse_msgmap(built):
    b, a, img = built
    ents = cpp.parse_msgmap(img, a["der_map"])
    assert [(e.message, e.code, e.id, e.last_id, e.sig) for e in ents] == [
        (WM_COMMAND, 0, 200, 200, 12), (WM_COMMAND, 0, 201, 205, 12), (WM_COMMAND, UPDATE_UI, 200, 200, 66),
        (WM_PAINT, 0, 0, 0, 19), (WM_TIMER, 0, 0, 0, 40)]
    assert ents[0].handler == a["h_open"] and ents[4].handler == a["h_tim"]
    assert cpp.entry_size(b.ps) == (24 if b.ps == 4 else 32)
    assert cpp.parse_msgmap(img, a["vt_der"]) is None            # a vtable is not a message map


def test_msgmap_rejects_bad_entries(built):
    b, a, img = built
    bad_code = b.data(b.ptr(0) + b.ptr(b.msgmap([(WM_COMMAND, 0, 1, 1, 12, b.rd_va)])))     # handler in data
    huge = b.msgmap([(0x20000, 0, 1, 1, 12, a["h_open"])])
    sig = b.msgmap([(WM_COMMAND, 0, 1, 1, 0x500, a["h_open"])])
    img = b.image()
    assert cpp.parse_msgmap(img, bad_code) is None
    assert cpp.parse_msgmap(img, huge) is None and cpp.parse_msgmap(img, sig) is None


def test_registered_message_keeps_pointer_sig(built):
    b, a, _ = built
    m = b.msgmap([(0xC000, 0, 0, 0, b.rd_va + 0x100, a["h_open"])])
    ents = cpp.parse_msgmap(b.image(), m)
    assert ents[0].sig == b.rd_va + 0x100


def test_find_msgmaps(built):
    b, a, img = built
    classes, slots, maps = cpp.parse_image(img)
    by_class = {m.cls: m for m in maps}
    # inherited slot: CPlain returns CBase's map and is not an owner of it
    assert set(by_class) == {"Ns::CBase", "CDerived", "SThunk", f"anon_{a['anon_map']:0{2 * b.ps}x}"}
    assert by_class["Ns::CBase"].map_addr == a["base_map"]
    assert by_class["CDerived"].map_addr == a["der_map"] and len(by_class["CDerived"].entries) == 5
    assert by_class["SThunk"].map_addr == a["thunk_map"]            # through the jmp stub
    anon = by_class[f"anon_{a['anon_map']:0{2 * b.ps}x}"]
    assert anon.entries[0].message == WM_NOTIFY


def test_unrelated_classes_sharing_a_map_both_listed():
    b = Builder(4)
    m = b.msgmap([(WM_COMMAND, 0, 1, 1, 12, b.stub())])
    g = b.getter(m)
    cols = []
    for n in ("X", "Y"):
        td = b.td(f".?AV{n}@@")
        cols.append(b.col(td, b.chd([(td, 0)])))
        b.vtable(cols[-1], [g])
    _, _, maps = cpp.parse_image(b.image())
    assert sorted(x.cls for x in maps) == ["X", "Y"]


# ── store, hints ───────────────────────────────────────────────────────────

def test_schema_and_migration(tmp_path):
    assert SCHEMA_VERSION >= 10 and 10 in MIGRATIONS and 9 in MIGRATIONS
    st = Store(tmp_path / "i.sqlite")
    for t in ("rtti_class", "vtable_slot", "msgmap_entry"):
        assert st.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0
    idx = {r[1] for r in st.db.execute("PRAGMA index_list(msgmap_entry)")}
    assert "msgmap_entry_by_ctrl" in idx
    assert [r[1] for r in st.db.execute("PRAGMA table_info(msgmap_entry)")] == [
        "binary_id", "class", "map_addr", "message", "code", "ctrl_id", "last_id", "sig", "handler", "seq"]
    assert [r[1] for r in st.db.execute("PRAGMA table_info(rtti_class)")] == [
        "binary_id", "name", "td_addr", "col_addr", "vtable_addr", "bases"]
    assert [r[1] for r in st.db.execute("PRAGMA table_info(vtable_slot)")] == [
        "binary_id", "vtable_addr", "slot", "target"]


def test_migration_from_v8(tmp_path):
    p = tmp_path / "old.sqlite"
    st = Store(p)
    for t in ("rtti_class", "vtable_slot", "msgmap_entry"):
        st.db.execute(f"DROP TABLE {t}")
    st.db.execute("UPDATE meta SET value='8' WHERE key='schema_version'")
    st.db.commit()
    st.close()
    st = Store(p)
    assert st.schema_version == SCHEMA_VERSION
    assert st.db.execute("SELECT COUNT(*) FROM msgmap_entry").fetchone()[0] == 0


def _store_with(tmp_path, built):
    b, a, img = built
    st = Store(tmp_path / "i.sqlite")
    bid = st.upsert_binary("aa" * 32, "app.exe", pointer_size=b.ps, image_base=b.base)
    classes, slots, maps = cpp.parse_image(img)
    cpp.store_rows(st, bid, classes, slots, maps)
    return st, bid, a


def test_store_rows_and_staleness(tmp_path, built):
    st, bid, a = _store_with(tmp_path, built)
    q = st.db.execute
    assert q("SELECT COUNT(*) FROM rtti_class WHERE binary_id=?", (bid,)).fetchone()[0] == 5
    r = q("SELECT name, td_addr, col_addr, vtable_addr, bases FROM rtti_class WHERE col_addr=?",
          (a["col_der"],)).fetchone()
    assert tuple(r) == ("CDerived", a["td_der"], a["col_der"], a["vt_der"], "Ns::CBase")
    assert q("SELECT target FROM vtable_slot WHERE binary_id=? AND vtable_addr=? AND slot=1",
             (bid, a["vt_der"])).fetchone()[0] == a["h_open"]
    rows = q("SELECT message, code, ctrl_id, last_id, sig, handler, seq FROM msgmap_entry "
             "WHERE binary_id=? AND class='CDerived' ORDER BY seq", (bid,)).fetchall()
    assert [tuple(r)[:3] for r in rows][:3] == [(WM_COMMAND, 0, 200), (WM_COMMAND, 0, 201),
                                                  (WM_COMMAND, UPDATE_UI, 200)]
    assert [r[6] for r in rows] == [0, 1, 2, 3, 4] and rows[1][3] == 205
    assert not cpp.stale(st, bid)
    st.set_meta(cpp.meta_key(bid), "0")
    assert cpp.stale(st, bid)
    cpp.store_rows(st, bid, [], {}, [])                           # idempotent: replaces the rows
    assert q("SELECT COUNT(*) FROM msgmap_entry").fetchone()[0] == 0


def test_hints(tmp_path, built):
    st, bid, a = _store_with(tmp_path, built)
    open_h = cpp.hints_for(st, bid, a["h_open"])
    assert open_h[0] == "CDerived::vslot 1"
    assert "handler WM_COMMAND id 200 of CDerived" in open_h
    assert any(h.startswith("handler WM_NOTIFY NM_CLICK id 300 of anon_") for h in open_h)
    assert cpp.hints_for(st, bid, a["h_upd"]) == ["handler UPDATE_COMMAND_UI id 200 of CDerived"]
    assert cpp.hints_for(st, bid, a["h_paint"]) == ["handler WM_PAINT of CDerived"]
    assert cpp.hints_for(st, bid, a["h_close"]) == [
        "CDerived::vslot 0", "handler WM_COMMAND id 201-205 of CDerived", "handler WM_COMMAND id 400 of SThunk"]
    assert cpp.hints_for(st, bid, a["virt"][0]) == ["Ns::CBase::vslot 0 (+2 classes)"]
    assert cpp.hints_for(st, bid, 0x1234) == []


def test_derive_binary_from_pe_file(tmp_path):
    from test_projects import make_pe
    pe = make_pe(tmp_path / "x.exe")
    st = Store(tmp_path / "i.sqlite")
    bid = st.upsert_binary("bb" * 32, "x.exe", pointer_size=4)
    assert cpp.derive_binary(st, bid, pe) == (0, 0, 0)
    assert not cpp.stale(st, bid)
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a pe")
    assert cpp.derive_binary(st, bid, junk) == (0, 0, 0)


# ── tools ──────────────────────────────────────────────────────────────────

def _ctx_with_rows(tmp_path, built):
    b, a, img = built
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    st.db.execute("UPDATE binary SET pointer_size=? WHERE id=?", (b.ps, bid))
    st.db.commit()
    classes, slots, maps = cpp.parse_image(img)
    cpp.store_rows(st, bid, classes, slots, maps)
    return ctx, st, bid, a, b


def test_rtti_classes_tool(tmp_path, built):
    ctx, st, bid, a, b = _ctx_with_rows(tmp_path, built)
    out = cpp_tools.rtti_classes(ctx).splitlines()
    assert len(out) == 5
    assert any(ln.startswith("CDerived vtable ") and ln.endswith("bases Ns::CBase") and f"slots 3" in ln
               for ln in out)
    assert f"0x{a['vt_der']:0{2 * b.ps}x}" in "\n".join(out)
    assert cpp_tools.rtti_classes(ctx, "base").splitlines()[0].startswith("Ns::CBase vtable")
    paged = cpp_tools.rtti_classes(ctx, limit=2).splitlines()
    assert len(paged) == 3 and paged[-1].startswith("… 3 more lines. cursor=")
    rest = cpp_tools.rtti_classes(ctx, limit=2, cursor=paged[-1].rsplit("cursor=", 1)[1]).splitlines()
    assert len(rest) == 3 and rest[-1].startswith("… 1 more lines. cursor=")   # 2 per page again
    last = cpp_tools.rtti_classes(ctx, limit=2, cursor=rest[-1].rsplit("cursor=", 1)[1]).splitlines()
    assert len(last) == 1 and not last[0].startswith("…")
    assert cpp_tools.rtti_classes(ctx, "zzz").startswith("no RTTI class matches")
    assert cpp_tools.rtti_classes(ctx, limit=0).startswith("error bad_args")


def test_vtable_tool(tmp_path, built):
    ctx, st, bid, a, b = _ctx_with_rows(tmp_path, built)
    out = cpp_tools.vtable(ctx, "CDerived").splitlines()
    assert out[0].startswith("CDerived vtable 0x") and "slots 3" in out[0]
    assert len(out) == 6 and out[2].startswith("[1] 0x")       # the two COLs (offsets 0 and 8) of CDerived
    by_addr = cpp_tools.vtable(ctx, f"0x{a['vt_base'] + b.ps:x}").splitlines()
    assert by_addr[0].startswith("Ns::CBase vtable") and by_addr[2].endswith("<-")
    assert cpp_tools.vtable(ctx, "cbase").splitlines()[0].startswith("Ns::CBase")
    assert cpp_tools.vtable(ctx, "C").startswith("error ambiguous")
    assert cpp_tools.vtable(ctx, "Nope").startswith("error not_found")
    assert cpp_tools.vtable(ctx, "0x10").startswith("error not_found")
    assert cpp_tools.vtable(ctx, "").startswith("error bad_target")
    # a named function shows its name
    st.insert_functions(bid, [{"entry": a["h_open"], "name": "OnOpen", "name_state": "auto",
                               "namespace": "CDerived"}])
    assert "CDerived::OnOpen" in cpp_tools.vtable(ctx, "CDerived")


def test_mfc_message_maps_tool(tmp_path, built):
    ctx, st, bid, a, b = _ctx_with_rows(tmp_path, built)
    st.insert_functions(bid, [{"entry": a["h_open"], "name": "OnFileOpen", "name_state": "auto",
                               "namespace": "CDerived"}])
    summary = cpp_tools.mfc_message_maps(ctx).splitlines()
    assert len(summary) == 4 and any(ln.startswith("CDerived map 0x") and ln.endswith("entries 5") for ln in summary)
    out = cpp_tools.mfc_message_maps(ctx, "CDerived").splitlines()
    assert out[0].startswith("CDerived map 0x") and len(out) == 6
    assert out[1].startswith("WM_COMMAND id 200 -> 0x") and out[1].endswith("CDerived::OnFileOpen")
    assert out[2].startswith("WM_COMMAND id 201-205 -> ")
    assert out[3].startswith("UPDATE_COMMAND_UI id 200 -> ")
    assert out[4].startswith("WM_PAINT -> ") and " id " not in out[4]
    assert out[5].startswith("WM_TIMER -> ")
    nm = cpp_tools.mfc_message_maps(ctx, "anon_").splitlines()
    assert nm[0].startswith("error ambiguous") or nm[0].startswith("anon_")
    inherited = cpp_tools.mfc_message_maps(ctx, "CPlain").splitlines()
    assert inherited[0] == "// CPlain has no message map of its own; inherited from Ns::CBase"
    assert inherited[1].startswith("Ns::CBase map ")
    assert cpp_tools.mfc_message_maps(ctx, "Nope").startswith("error not_found")
    assert cpp_tools.mfc_message_maps(ctx, "sthunk").splitlines()[0].startswith("SThunk map")


def test_function_tool_shows_hints(tmp_path, built):
    from airlock.server.tools import core
    ctx, st, bid, a, b = _ctx_with_rows(tmp_path, built)
    # the fixture binary has functions at 0x401xxx: point the tables at one of them
    st.db.execute("UPDATE vtable_slot SET target=0x401200 WHERE vtable_addr=? AND slot=1", (a["vt_der"],))
    st.db.execute("UPDATE msgmap_entry SET handler=0x401200 WHERE class='CDerived' AND seq=0")
    st.db.commit()
    out = core.function(ctx, "FUN_00401200", view="signature")
    assert "CDerived::vslot 1" in out and "handler WM_COMMAND id 200 of CDerived" in out


def test_catalog_not_clean_safe():
    for t in ("rtti_classes", "vtable", "mfc_message_maps"):
        assert not CATALOG[t].clean_safe
        s = roles.SessionState(roles.CLEAN, None)
        assert roles.gate(s, t).startswith("error wrong_role")


def test_ensure_derives_once(tmp_path):
    from test_projects import make_pe
    st = Store(tmp_path / "i.sqlite")
    bid = st.upsert_binary("cc" * 32, "y.exe", pointer_size=4)
    b = st.get_binary_by_id(bid)
    assert cpp.ensure(st, b, tmp_path / "missing") is False and cpp.stale(st, bid)
    pe = make_pe(tmp_path / "y.exe")
    assert cpp.ensure(st, b, pe) is True and not cpp.stale(st, bid)
    assert cpp.ensure(st, b, pe) is False
