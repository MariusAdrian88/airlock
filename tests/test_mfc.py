"""MFC classes without RTTI (CRuntimeClass, vtable groups, dialog constructors) and dispatch / interface /
event sink maps: synthetic byte images (32-bit and 64-bit). All names are invented."""

from __future__ import annotations

import struct

import pytest

from airlock.index.migrations import MIGRATIONS
from airlock.index.store import SCHEMA_VERSION, Store
from airlock.server import cpp, mfc, uijoin
from airlock.server.tools import cpp as cpp_tools
from test_cpp import Builder
from test_tools import fill, make_ctx
from test_ui_join import proj  # noqa: F401  (fixture)

WM_COMMAND, WM_SIZE = 0x111, 0x05
IDISPATCH = struct.pack("<IHH8s", 0x20400, 0, 0, bytes.fromhex("c000000000000046"))


def runtime_class(b: Builder, name: str, size: int, base: int = 0, create: int = 0) -> int:
    nm = b.data(name.encode() + b"\0", 1)
    if b.ps == 4:
        raw = struct.pack("<IIIIIII", nm, size, 0xFFFF, create, base, 0, 0)
    else:
        raw = struct.pack("<QIIQQQQ", nm, size, 0xFFFF, create, base, 0, 0)
    return b.data(raw)


def disp_entries(b: Builder, entries: list[tuple], tail: tuple | None = None, wide: bool = False) -> int:
    """entries: (name | None, dispid, params | None, vt, pfn, pfn_set, offset, flags). ``wide``: UTF-16 names
    (a Unicode build: ``LPCTSTR``)."""
    fmt = mfc._fmt(b.ps)
    allones = 2 ** (8 * b.ps) - 1
    raw = b""
    for name, did, params, vt, pfn, pfs, off, flags in entries + [(None, -1, None, 0xFF, 0, 0, allones, 0)]:
        if name is None:
            n = 0
        else:
            n = b.data(name.encode("utf-16-le") + b"\0\0", 2) if wide else b.data(name.encode() + b"\0", 1)
        pr = b.data(params + b"\0", 1) if params else 0
        raw += struct.pack(fmt, n, did, pr, vt, pfn, pfs, off, flags)
        if tail is not None:
            raw += struct.pack("<II", *(tail if name is not None else (0, 0)))
    return b.data(raw)


def dispmap(b: Builder, entries: list[tuple], base: int = 0, wide: bool = False) -> int:
    ents = disp_entries(b, entries, wide=wide)
    cnt = b.data(struct.pack("<I", 0xFFFFFFFF), 4)
    stock = b.data(struct.pack("<I", 0), 4)
    return b.data(b.ptr(base) + b.ptr(ents) + b.ptr(cnt) + b.ptr(stock))


def eventmap(b: Builder, entries: list[tuple], ctrl: tuple[int, int]) -> int:
    ents = disp_entries(b, entries, tail=ctrl)
    cnt = b.data(struct.pack("<I", 0xFFFFFFFF), 4)
    return b.data(b.ptr(0) + b.ptr(ents) + b.ptr(cnt))


def intmap(b: Builder, entries: list[tuple[bytes, int]]) -> int:
    raw = b""
    for guid, off in entries:
        raw += b.ptr(b.data(guid, 4)) + b.ptr(off)
    raw += b.ptr(0) + b.ptr(2 ** (8 * b.ps) - 1)
    return b.data(b.ptr(0) + b.ptr(b.data(raw)))


def dialog_ctor(b: Builder, dialog_id: int, vtable: int, target: int) -> int:
    """push [ebp+8]; push id; mov ecx,esi; call target; mov [esi], vtable; ret  (32-bit)."""
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    call_at = va + 3 + 5 + 2
    return b.code(b"\xff\x75\x08" + b"\x68" + struct.pack("<I", dialog_id) + b"\x8b\xce" + b"\xe8"
                  + struct.pack("<i", target - (call_at + 5)) + b"\xc7\x06" + struct.pack("<I", vtable) + b"\xc3")


def dialog_ctor64(b: Builder, dialog_id: int, vtable: int, target: int, reg_form: int = 0) -> int:
    """mov r8, rdx; mov edx, id; mov rcx, rbx; call target; lea rax,[rip+vtable]; mov [rbx], rax; ret (64-bit);
    reg_form 1: the id goes to r8d (mov r8d, id) instead of edx."""
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    head = (b"\x4c\x8b\xc2" + b"\xba" + struct.pack("<I", dialog_id) if reg_form == 0
            else b"\x48\x8b\xd6" + b"\x41\xb8" + struct.pack("<I", dialog_id))
    call_at = va + len(head) + 3
    body = head + b"\x48\x8b\xcb" + b"\xe8" + struct.pack("<i", target - (call_at + 5))
    lea_at = va + len(body)
    body += b"\x48\x8d\x05" + struct.pack("<i", vtable - (lea_at + 7)) + b"\x48\x89\x03" + b"\xc3"
    return b.code(body)


def build(ps: int):
    """CFoo (own CRuntimeClass, map, dispatch map, interface map); CBar : CFoo without CRuntimeClass of its
    own (own map, inherits the dispatch slot); CDlg (rc, map, event sink map); CDlg2 : CDlg without rc
    whose constructor passes dialog 1001; CRtti with RTTI and a dispatch map."""
    b = Builder(ps)
    h = {n: b.stub() for n in ("open", "close", "ok", "ok2", "do", "get", "set", "after", "ev", "create", "size")}
    msg_foo = b.msgmap([(WM_COMMAND, 0, 100, 100, 12, h["open"])])
    msg_bar = b.msgmap([(WM_COMMAND, 0, 200, 200, 12, h["close"]), (WM_SIZE, 0, 0, 0, 19, h["size"])], base=msg_foo)
    msg_dlg = b.msgmap([(WM_COMMAND, 0, 1, 1, 12, h["ok"])])
    msg_dlg2 = b.msgmap([(WM_COMMAND, 0, 1, 1, 12, h["ok2"])], base=msg_dlg)
    msg_rtti = b.msgmap([(WM_COMMAND, 0, 300, 300, 12, h["open"])])
    disp_foo = dispmap(b, [("DoIt", 2, bytes([3, 0x4E]), 0, h["do"], 0, 0, 0),
                           ("Name", 5, None, 8, h["get"], h["set"], 0, 0),
                           ("Count", -1, None, 3, 0, h["after"], 0x20, 0),
                           (None, -501, None, 3, 0, 0, 0, 1)])
    disp_rtti = dispmap(b, [("Ping", 1, None, 11, h["do"], 0, 0, 0)])
    int_foo = intmap(b, [(IDISPATCH, 16)])
    ev_dlg = eventmap(b, [("", 7, bytes([3]), 11, h["ev"], 0, 0, 0)], ctrl=(1000, 1000))
    g = {k: b.getter(v) for k, v in dict(msg_foo=msg_foo, msg_bar=msg_bar, msg_dlg=msg_dlg, msg_dlg2=msg_dlg2,
                                         msg_rtti=msg_rtti, disp_foo=disp_foo, disp_rtti=disp_rtti,
                                         int_foo=int_foo, ev_dlg=ev_dlg).items()}
    rc_foo = runtime_class(b, "CFoo", 100, 0, h["create"])
    g_rc_foo = b.getter(rc_foo)
    vt_foo = b.vtable(None, [g_rc_foo, b.stub(), g["msg_foo"], g["disp_foo"], g["int_foo"]])
    rc_dlg = runtime_class(b, "CDlg", 200, rc_foo)
    g_rc_dlg = b.getter(rc_dlg)
    vt_dlg = b.vtable(None, [g_rc_dlg, b.stub(), g["msg_dlg"], g["ev_dlg"]])
    vt_bar = b.vtable(None, [g_rc_foo, b.stub(), g["msg_bar"], g["disp_foo"], g["int_foo"]])
    vt_dlg2 = b.vtable(None, [g_rc_dlg, b.stub(), g["msg_dlg2"], g["ev_dlg"]])
    td = b.td(".?AVCRtti@@")
    vt_rtti = b.vtable(b.col(td, b.chd([(td, 0)])), [b.stub(), g["msg_rtti"], g["disp_rtti"]])
    base_ctor = b.stub()
    if ps == 4:
        dialog_ctor(b, 1000, vt_dlg, base_ctor)
        dialog_ctor(b, 1001, vt_dlg2, base_ctor)
    else:
        dialog_ctor64(b, 1000, vt_dlg, base_ctor)
        dialog_ctor64(b, 1001, vt_dlg2, base_ctor)
    return b, dict(msg_foo=msg_foo, msg_bar=msg_bar, msg_dlg=msg_dlg, msg_dlg2=msg_dlg2, msg_rtti=msg_rtti,
                   disp_foo=disp_foo, disp_rtti=disp_rtti, int_foo=int_foo, ev_dlg=ev_dlg, rc_foo=rc_foo,
                   rc_dlg=rc_dlg, vt_foo=vt_foo, vt_bar=vt_bar, vt_dlg=vt_dlg, vt_dlg2=vt_dlg2, h=h)


@pytest.fixture(params=[4, 8], ids=["x86", "x64"])
def built(request, monkeypatch):
    monkeypatch.setattr(mfc, "_dialog_ids", lambda path: {1000: "Main", 1001: "About &Box..."})
    b, a = build(request.param)
    return b, a, b.image()


def analysed(built):
    b, a, img = built
    classes, slots, maps = cpp.parse_image(img)
    assert all(m.cls.startswith("anon_") or m.cls == "CRtti" for m in maps)
    return classes, slots, maps, mfc.analyse(img, classes, slots, maps, None)


def test_runtime_classes(built):
    b, a, img = built
    rcs = mfc.find_runtime_classes(img)
    assert {r.name for r in rcs.values()} == {"CFoo", "CDlg"}
    assert rcs[a["rc_dlg"]].base_name == "CFoo" and rcs[a["rc_dlg"]].size == 200
    assert rcs[a["rc_foo"]].create == a["h"]["create"]


def test_anonymous_classes_get_names(built):
    b, a, img = built
    classes, slots, maps, res = analysed(built)
    by_addr = {m.map_addr: m.cls for m in maps}
    w = 2 * b.ps
    assert by_addr[a["msg_foo"]] == "CFoo"
    assert by_addr[a["msg_dlg"]] == "CDlg"
    assert by_addr[a["msg_bar"]] == f"anon_CFoo_{a['msg_bar']:0{w}x}"          # derived: base from CRuntimeClass
    assert by_addr[a["msg_dlg2"]] == "Dialog_About_Box"                         # dialog 1001 of the constructor
    rows = {c.name: c for c in res.classes}
    assert rows["CFoo"].source == "rc" and rows["CFoo"].size == 100 and rows["CFoo"].rc == a["rc_foo"]
    assert rows["CDlg"].base == "CFoo"                                          # no base map: the base CRuntimeClass
    bar = rows[f"anon_CFoo_{a['msg_bar']:0{w}x}"]
    assert bar.source == "inherited" and bar.base == "CFoo" and bar.rc == 0 and bar.map_addr == a["msg_bar"]
    assert rows["CDlg"].dialog == "1000" and rows["Dialog_About_Box"].dialog == "1001"
    assert rows["Dialog_About_Box"].base == "CDlg" and rows["Dialog_About_Box"].source == "dialog"


def test_dispatch_map_entries(built):
    b, a, img = built
    classes, slots, maps, res = analysed(built)
    disp = [m for m in res.maps if m.kind == "dispatch"]
    assert sorted(m.cls for m in disp) == ["CFoo", "CRtti"]                      # CBar inherits it: not repeated
    foo = next(m for m in disp if m.cls == "CFoo")
    assert foo.addr == a["disp_foo"] and len(foo.entries) == 4
    doit, name, count, stock = foo.entries
    assert (doit.name, doit.id, doit.vt, doit.pfn, doit.pfn_set) == ("DoIt", 2, 0, a["h"]["do"], 0)
    assert doit.extra == "args long,LPCSTR"
    assert (name.name, name.vt, name.pfn, name.pfn_set) == ("Name", 8, a["h"]["get"], a["h"]["set"])
    assert (count.id, count.pfn, count.pfn_set, count.extra) == (-1, 0, a["h"]["after"], "offset 0x20")
    assert stock.flags == 1 and stock.name == "" and stock.id == -501
    assert mfc.STOCK_DISPIDS[stock.id] == "BackColor"
    assert next(m for m in disp if m.cls == "CRtti").entries[0].name == "Ping"


def test_interface_and_event_maps(built):
    b, a, img = built
    classes, slots, maps, res = analysed(built)
    intf = [m for m in res.maps if m.kind == "interface"]
    assert [(m.cls, m.entries[0].name, m.entries[0].id) for m in intf] == [("CFoo", "IDispatch", 16)]
    ev = [m for m in res.maps if m.kind == "event"]
    assert [m.cls for m in ev] == ["CDlg"]
    e = ev[0].entries[0]
    assert (e.id, e.vt, e.pfn, e.extra) == (7, 11, a["h"]["ev"], "args long; ctrl 1000") or \
        (e.id, e.vt, e.pfn) == (7, 11, a["h"]["ev"])
    assert "ctrl 1000" in e.extra


def test_message_maps_are_not_dispatch_maps(built):
    b, a, img = built
    msg = {a["msg_foo"], a["msg_bar"]}
    for addr in (a["msg_foo"], a["msg_bar"]):
        assert mfc.kind_of(img, addr, set(), {}) is None
    assert mfc.kind_of(img, a["disp_foo"], msg, {})[0] == "dispatch"
    assert mfc.kind_of(img, a["int_foo"], msg, {})[0] == "interface"
    assert mfc.kind_of(img, a["ev_dlg"], msg, {})[0] == "event"
    assert mfc.parse_dispmap(img, a["int_foo"]) is None and mfc.parse_intmap(img, a["disp_foo"]) is None


def test_ctor_dialogs_needs_two_classes_and_known_ids():
    b = Builder(4)
    base = b.stub()
    vt1, vt2, vt3 = (b.vtable(None, [b.stub()]) for _ in range(3))
    dialog_ctor(b, 1000, vt1, base)
    dialog_ctor(b, 1001, vt2, base)
    dialog_ctor(b, 77, vt3, b.stub())                        # unknown id, own target
    img = b.image()
    assert mfc.ctor_dialogs(img, [vt1, vt2, vt3], {1000, 1001, 77}) == {vt1: 1000, vt2: 1001}
    assert mfc.ctor_dialogs(img, [vt1, vt2], {1000}) == {}   # a single class cannot confirm the target
    assert mfc.ctor_dialogs(Builder(8).image(), [], {1}) == {}


def test_ctor_dialogs_64bit_forms():
    b = Builder(8)
    base = b.stub()
    vt1, vt2, vt3, vt4 = (b.vtable(None, [b.stub()]) for _ in range(4))
    dialog_ctor64(b, 1000, vt1, base)
    dialog_ctor64(b, 1001, vt2, base, reg_form=1)                       # id in r8d
    dialog_ctor64(b, 77, vt3, b.stub())                                 # unknown id, own target
    # the id and call sit far before the vtable store: the call of another function, not this constructor's
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    far = b"\xba" + struct.pack("<I", 1000) + b"\xe8" + struct.pack("<i", base - (va + 10)) + b"\x90" * 60
    lea_at = va + len(far)
    b.code(far + b"\x48\x8d\x05" + struct.pack("<i", vt4 - (lea_at + 7)) + b"\x48\x89\x03\xc3")
    img = b.image()
    got = mfc.ctor_dialogs(img, [vt1, vt2, vt3, vt4], {1000, 1001, 77})
    assert got == {vt1: 1000, vt2: 1001}
    assert mfc.ctor_dialogs(img, [vt1, vt2], {1000}) == {}


def test_symbol_class_needs_clear_votes():
    fw = {"CWnd"}
    sym = {1: "CMyWnd", 2: "CMyWnd", 3: "CWnd", 4: "CWnd", 5: "Other"}
    assert mfc.symbol_class(sym, [1, 2, 3, 4, 99], fw) == "CMyWnd"           # framework namespaces do not vote
    assert mfc.symbol_class(sym, [1, 3], fw) is None                         # a single vote
    assert mfc.symbol_class(sym, [1, 2, 5], fw) == "CMyWnd"                  # 2 of 3
    assert mfc.symbol_class({1: "A", 2: "A", 3: "B", 4: "B"}, [1, 2, 3, 4], fw) is None
    assert mfc.symbol_class({1: "std::x", 2: "std::x"}, [1, 2], fw) is None  # not an identifier


def test_names_helpers():
    assert mfc.ident("&Save As...") == "Save_As"
    assert mfc.ident("File\tCtrl+S") == "File"
    assert mfc.ident("a" * 40, 8) == "aaaaaaaa"
    assert mfc.vts_name(0x45) == "double&" and mfc.vts_name(0x4E) == "LPCSTR" and mfc.vts_name(8) == "BSTR"
    assert mfc.guid_name(IDISPATCH) == "IDispatch"
    assert mfc.guid_name(bytes(range(16))).startswith("{03020100-0504-0706-0809-0A0B0C0D0E0F")


PROP_NOTIFY = struct.pack("<IHH8s", 0x9BFBBC02, 0xEFF1, 0x101A, bytes.fromhex("84ed00aa00341d07"))


def build_conn(ps: int):
    """COleThing (rc; vtable slots: connection map, interface map), CRttiOle (RTTI; same two slots),
    CLone (rc; only an interface map)."""
    b = Builder(ps)
    conn = intmap(b, [(PROP_NOTIFY, 0x30)])
    iface = intmap(b, [(IDISPATCH, 16)])
    conn2 = intmap(b, [(PROP_NOTIFY, 0x40), (IDISPATCH, 0x48)])
    iface2 = intmap(b, [(IDISPATCH, 16), (IDISPATCH, 24)])
    iface3 = intmap(b, [(PROP_NOTIFY, 8)])                      # an interface map: nothing precedes it
    rc1 = runtime_class(b, "COleThing", 80)
    vt1 = b.vtable(None, [b.getter(rc1), b.stub(), b.getter(conn), b.getter(iface)])
    td = b.td(".?AVCRttiOle@@")
    vt2 = b.vtable(b.col(td, b.chd([(td, 0)])), [b.stub(), b.getter(conn2), b.getter(iface2)])
    rc3 = runtime_class(b, "CLone", 40)
    b.vtable(None, [b.getter(rc3), b.stub(), b.getter(iface3)])
    return b, dict(conn=conn, iface=iface, conn2=conn2, iface2=iface2, iface3=iface3, vt1=vt1, vt2=vt2)


@pytest.fixture(params=[4, 8], ids=["x86", "x64"])
def conn_built(request):
    b, a = build_conn(request.param)
    return b, a, b.image()


def test_connection_maps_are_told_from_interface_maps(conn_built):
    b, a, img = conn_built
    classes, slots, maps = cpp.parse_image(img)
    res = mfc.analyse(img, classes, slots, maps, None)
    got = sorted((m.cls, m.kind, m.addr) for m in res.maps)
    assert got == sorted([("COleThing", "connection", a["conn"]), ("COleThing", "interface", a["iface"]),
                          ("CRttiOle", "connection", a["conn2"]), ("CRttiOle", "interface", a["iface2"]),
                          ("CLone", "interface", a["iface3"])])
    conn = next(m for m in res.maps if m.addr == a["conn"])
    assert [(e.name, e.id) for e in conn.entries] == [("IPropertyNotifySink", 0x30)]
    both = next(m for m in res.maps if m.addr == a["conn2"])
    assert [e.name for e in both.entries] == ["IPropertyNotifySink", "IDispatch"]


def test_mark_connections_needs_two_different_adjacent_maps(conn_built):
    b, a, img = conn_built
    cache: dict = {}
    mfc.mark_connections(img, [a["iface"], a["iface"]], set(), cache)           # the same map twice
    mfc.mark_connections(img, [None, a["iface3"], None], set(), cache)
    assert mfc.kind_of(img, a["iface"], set(), cache)[0] == "interface"
    assert mfc.kind_of(img, a["iface3"], set(), cache)[0] == "interface"
    mfc.mark_connections(img, [a["conn"], a["iface"]], set(), cache)
    assert mfc.kind_of(img, a["conn"], set(), cache)[0] == "connection"


def test_tool_shows_connection_maps(tmp_path, conn_built):
    b, a, img = conn_built
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    st.db.execute("UPDATE binary SET pointer_size=? WHERE id=?", (b.ps, bid))
    st.db.commit()
    classes, slots, maps = cpp.parse_image(img)
    cpp.store_rows(st, bid, classes, slots, maps, mfc.analyse(img, classes, slots, maps, None))
    summary = cpp_tools.mfc_message_maps(ctx).splitlines()
    assert any(ln.startswith("COleThing connection map 0x") and ln.endswith("entries 1") for ln in summary)
    out = cpp_tools.mfc_message_maps(ctx, "COleThing").splitlines()
    i = next(k for k, ln in enumerate(out) if " connection map " in ln)
    assert out[i + 1] == "connection IPropertyNotifySink offset 0x30"
    j = next(k for k, ln in enumerate(out) if " interface map " in ln)
    assert out[j + 1] == "interface IDispatch offset 0x10"


def test_unicode_dispatch_names(conn_built):
    b, a, img = conn_built
    b = Builder(a and b.ps)
    h = b.stub()
    dm = dispmap(b, [("RefreshView", 1, None, 0, h, 0, 0, 0), ("A", 2, bytes([3]), 0, h, 0, 0, 0),
                     ("Count", 3, None, 3, 0, 0, 0x20, 0)], wide=True)
    ents = mfc.parse_dispmap(b.image(), dm)
    assert [e.name for e in ents] == ["RefreshView", "A", "Count"]       # a one-letter name stays one letter
    assert ents[1].extra == "args long" and ents[2].extra == "offset 0x20"
    ansi = dispmap(b, [("Ab", 1, None, 0, h, 0, 0, 0), ("C", 2, None, 0, h, 0, 0, 0)])
    assert [e.name for e in mfc.parse_dispmap(b.image(), ansi)] == ["Ab", "C"]


# ── names from symbols and dialog resources ───────────────────────────────

def test_symbol_names_the_derived_class(built):
    b, a, img = built
    classes, slots, maps = cpp.parse_image(img)
    h = a["h"]
    sym = {h["close"]: "CBarWnd", h["size"]: "CBarWnd", h["open"]: "CFoo"}      # CFoo owns a runtime class
    res = mfc.analyse(img, classes, slots, maps, None, sym)
    by_addr = {m.map_addr: m.cls for m in maps}
    assert by_addr[a["msg_bar"]] == "CBarWnd" and by_addr[a["msg_foo"]] == "CFoo"
    row = next(c for c in res.classes if c.name == "CBarWnd")
    assert row.source == "symbols" and row.base == "CFoo" and row.map_addr == a["msg_bar"]


def test_one_symbol_vote_is_not_enough(built):
    b, a, img = built
    classes, slots, maps = cpp.parse_image(img)
    res = mfc.analyse(img, classes, slots, maps, None, {a["h"]["close"]: "CBarWnd"})
    assert {m.map_addr: m.cls for m in maps}[a["msg_bar"]].startswith("anon_CFoo_")
    assert all(c.source != "symbols" for c in res.classes)


def build_join(ps: int):
    """CDialog (rc, its own map) and a class derived from it whose map handles control 600; no constructor."""
    b = Builder(ps)
    h = b.stub()
    msg0 = b.msgmap([(WM_COMMAND, 0, 1, 1, 12, h)])
    msg_d = b.msgmap([(WM_COMMAND, 0, 600, 600, 12, h), (WM_COMMAND, 0, 1, 1, 12, h)])
    msg_f = b.msgmap([(WM_COMMAND, 0, 600, 600, 12, h)])
    rc = runtime_class(b, "CDialog", 100)
    b.vtable(None, [b.getter(rc), b.stub(), b.getter(msg0)])
    b.vtable(None, [b.getter(rc), b.stub(), b.getter(msg_d)])
    rc2 = runtime_class(b, "CFrameWnd", 100)                    # not a dialog: no join
    b.vtable(None, [b.getter(rc2), b.stub(), b.getter(b.msgmap([(WM_COMMAND, 0, 7, 7, 12, h)]))])
    b.vtable(None, [b.getter(rc2), b.stub(), b.getter(msg_f)])
    return b, msg_d, msg_f


@pytest.mark.parametrize("ps", [4, 8], ids=["x86", "x64"])
def test_dialog_class_named_by_its_control_ids(ps, monkeypatch):
    monkeypatch.setattr(mfc, "_dialog_ids", lambda path: {1000: "Main", 1001: "About &Box..."})
    monkeypatch.setattr(mfc, "_dialog_ctrls", lambda path: {1000: {1, 2, 500}, 1001: {1, 2, 600}})
    b, msg_d, msg_f = build_join(ps)
    img = b.image()
    classes, slots, maps = cpp.parse_image(img)
    res = mfc.analyse(img, classes, slots, maps, None)
    by_addr = {m.map_addr: m.cls for m in maps}
    assert by_addr[msg_d] == "Dialog_About_Box"
    assert by_addr[msg_f].startswith("anon_CFrameWnd_")                   # base is no dialog class: no join
    row = next(c for c in res.classes if c.name == "Dialog_About_Box")
    assert row.dialog == "1001" and row.source == "dialog" and row.base == "CDialog"


@pytest.mark.parametrize("ctrls", [{1000: {1, 600}, 1001: {1, 600}}, {1000: {1, 2}, 1001: {1, 3}}],
                         ids=["two dialogs fit", "none fits"])
def test_dialog_join_needs_exactly_one_dialog(ctrls, monkeypatch):
    monkeypatch.setattr(mfc, "_dialog_ids", lambda path: {1000: "Main", 1001: "About"})
    monkeypatch.setattr(mfc, "_dialog_ctrls", lambda path: ctrls)
    b, msg_d, _ = build_join(4)
    img = b.image()
    classes, slots, maps = cpp.parse_image(img)
    mfc.analyse(img, classes, slots, maps, None)
    assert {m.map_addr: m.cls for m in maps}[msg_d].startswith("anon_CDialog_")


def test_map_dialog_rules():
    ents = lambda *ids: [cpp.MsgEntry(WM_COMMAND, 0, i, i, 12, 0) for i in ids]      # noqa: E731
    assert mfc.map_dialog(ents(600, 1), {5: {1, 600}}) == 5
    assert mfc.map_dialog(ents(1, 2), {5: {1, 2}}) is None                  # only IDOK..IDHELP
    assert mfc.map_dialog([cpp.MsgEntry(WM_SIZE, 0, 0, 0, 19, 0)], {5: {1}}) is None
    assert mfc.map_dialog([cpp.MsgEntry(WM_COMMAND, 0, 600, 700, 12, 0)], {5: {600}}) is None   # a range


# ── store, tool ────────────────────────────────────────────────────────────

def _ctx_with_mfc(tmp_path, built):
    b, a, img = built
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    st.db.execute("UPDATE binary SET pointer_size=? WHERE id=?", (b.ps, bid))
    st.db.commit()
    classes, slots, maps = cpp.parse_image(img)
    res = mfc.analyse(img, classes, slots, maps, None)
    cpp.store_rows(st, bid, classes, slots, maps, res)
    return ctx, st, bid, a, b


def test_schema_and_migration(tmp_path):
    assert SCHEMA_VERSION >= 14 and 14 in MIGRATIONS
    st = Store(tmp_path / "i.sqlite")
    assert [r[1] for r in st.db.execute("PRAGMA table_info(mfc_map_entry)")] == [
        "binary_id", "class", "kind", "map_addr", "seq", "name", "id", "vt", "flags", "pfn", "pfn_set", "extra"]
    assert [r[1] for r in st.db.execute("PRAGMA table_info(mfc_class)")][:4] == [
        "binary_id", "name", "vtable_addr", "rc_addr"]
    st.db.execute("DROP TABLE mfc_class")
    st.db.execute("DROP TABLE mfc_map_entry")
    st.db.execute("UPDATE meta SET value='13' WHERE key='schema_version'")
    st.db.commit()
    st.close()
    st = Store(tmp_path / "i.sqlite")
    assert st.schema_version == SCHEMA_VERSION
    assert st.db.execute("SELECT COUNT(*) FROM mfc_map_entry").fetchone()[0] == 0


def test_store_rows_and_rederive(tmp_path, built):
    ctx, st, bid, a, b = _ctx_with_mfc(tmp_path, built)
    q = st.db.execute
    assert q("SELECT COUNT(*) FROM mfc_map_entry WHERE binary_id=? AND kind='dispatch'", (bid,)).fetchone()[0] == 5
    r = q("SELECT name, id, vt, pfn, pfn_set, extra FROM mfc_map_entry WHERE class='CFoo' AND name='DoIt'").fetchone()
    assert tuple(r) == ("DoIt", 2, 0, a["h"]["do"], None, "args long,LPCSTR")
    assert q("SELECT source FROM mfc_class WHERE name='CFoo'").fetchone()[0] == "rc"
    assert q("SELECT COUNT(*) FROM msgmap_entry WHERE class='CFoo'").fetchone()[0] == 1
    cpp.store_rows(st, bid, [], {}, [], None)                           # replaces everything
    assert q("SELECT COUNT(*) FROM mfc_map_entry").fetchone()[0] == 0 and q("SELECT COUNT(*) FROM mfc_class").fetchone()[0] == 0
    assert cpp.CPP_VERSION >= 2


def test_mfc_message_maps_shows_automation_maps(tmp_path, built):
    ctx, st, bid, a, b = _ctx_with_mfc(tmp_path, built)
    st.insert_functions(bid, [{"entry": a["h"]["do"], "name": "DoIt", "name_state": "auto", "namespace": "CFoo"}])
    summary = cpp_tools.mfc_message_maps(ctx).splitlines()
    assert any(ln.startswith("CFoo dispatch map 0x") and ln.endswith("entries 4") for ln in summary)
    assert any(ln.startswith("CFoo interface map 0x") and ln.endswith("entries 1") for ln in summary)
    assert any(ln.startswith("CDlg event map 0x") for ln in summary)
    out = cpp_tools.mfc_message_maps(ctx, "CFoo").splitlines()
    assert out[0].startswith("CFoo map 0x") and out[1].startswith("WM_COMMAND id 100 -> ")
    i = next(k for k, ln in enumerate(out) if " dispatch map " in ln)
    assert out[i + 1].startswith("method DoIt(long, LPCSTR) -> void dispid 2 -> 0x") and out[i + 1].endswith("CFoo::DoIt")
    assert out[i + 2].startswith("property Name BSTR dispid 5 get 0x") and " set 0x" in out[i + 2]
    assert out[i + 3].startswith("property Count long dispid auto offset 0x20 notify 0x")
    assert out[i + 4] == "stock BackColor dispid -501 long"
    assert out[i + 5].startswith("CFoo interface map 0x") and out[i + 6] == "interface IDispatch offset 0x10"
    ev = cpp_tools.mfc_message_maps(ctx, "CDlg").splitlines()
    assert any(ln.startswith("event dispid 7 ctrl 1000 -> 0x") for ln in ev)
    only = cpp_tools.mfc_message_maps(ctx, "CRtti").splitlines()                 # RTTI class: its own dispatch map
    assert any(ln.startswith("method Ping() -> BOOL dispid 1 -> 0x") for ln in only)
    assert cpp_tools.mfc_message_maps(ctx, "Nope").startswith("error not_found")


def test_derived_class_name_in_tool(tmp_path, built):
    ctx, st, bid, a, b = _ctx_with_mfc(tmp_path, built)
    out = cpp_tools.mfc_message_maps(ctx, f"anon_CFoo_{a['msg_bar']:0{2 * b.ps}x}").splitlines()
    assert out[0].startswith("anon_CFoo_") and "entries 2" in out[0]
    assert any(ln.startswith("WM_SIZE -> ") and " as OnSize" in ln for ln in out)       # nothing better: a wizard name
    assert any(ln.startswith("WM_COMMAND id 200 -> ") and " as OnCommand_200" in ln for ln in out)


def test_fnfix_candidates_include_dispatch_handlers(tmp_path, built):
    from airlock.server import fnfix
    ctx, st, bid, a, b = _ctx_with_mfc(tmp_path, built)
    cands = set(fnfix.candidates(st, bid))
    assert {a["h"]["do"], a["h"]["get"], a["h"]["set"], a["h"]["after"], a["h"]["ev"]} <= cands


# ── handler names ──────────────────────────────────────────────────────────

def test_suggested_names(proj):  # noqa: F811
    ctx, st, bid, h = proj
    ui = uijoin.UiIndex(st, bid)
    by_addr = {x.addr: x for x in ui.handlers}
    assert ui.suggest(by_addr[h["open"]]) in ("OnCommand_100_Open", "OnUpdateCommand_100_Open")
    cmds = {ui.suggest(x) for x in ui.handlers}
    assert "OnCommand_100_Open" in cmds and "OnUpdateCommand_100_Open" in cmds
    assert "OnBnClicked_Browse" in cmds                                  # button 1000 "&Browse..."
    assert any(c.startswith("OnEnChange_1001") for c in cmds)            # edit without caption: the id
    assert any(c.startswith("OnCommand_101_110") for c in cmds)          # a range
    assert uijoin.window_message_name(0x05) == "OnSize"
    assert uijoin.window_message_name(0xC000) == "OnRegisteredMessage"
    assert uijoin.window_message_name(0x0401).startswith("OnMessage_WM_USER")


def test_name_of_uses_suggestion_only_for_unnamed_functions(proj):  # noqa: F811
    ctx, st, bid, h = proj
    ui = uijoin.UiIndex(st, bid)
    hd = next(x for x in ui.handlers if x.addr == h["open"] and not x.is_update)
    assert ui.name_of(hd) == "CMainFrame::OnFileOpen"                    # a real name wins
    st.db.execute("UPDATE function SET name='FUN_00401000', namespace=NULL WHERE binary_id=? AND entry=?",
                  (bid, h["open"]))
    st.db.commit()
    ui = uijoin.UiIndex(st, bid)
    assert ui.name_of(hd) == "CMainFrame::OnCommand_100_Open (FUN_00401000)"
    hints = uijoin.function_hints(st, bid, h["open"])
    assert "likely CMainFrame::OnCommand_100_Open" in hints
    assert uijoin.is_unnamed(None) and not uijoin.is_unnamed(st.function_at(bid, h["upd"]))


# ── stack objects, shared MFC (no CRuntimeClass of the dialog class), connection slot ──────────────────────

def raw_ctor32(b: Builder, dialog_id: int, vtable: int, target: int, store: bytes) -> int:
    """push 0; push id; lea ecx,[esp+8]; call target; <store: mov dword [mem], imm32 with the vtable>; ret."""
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    head = b"\x6a\x00" + b"\x68" + struct.pack("<I", dialog_id) + b"\x8d\x4c\x24\x08"
    call = b"\xe8" + struct.pack("<i", target - (va + len(head) + 5))
    return b.code(head + call + store + struct.pack("<I", vtable) + b"\xc3")


def raw_ctor64(b: Builder, dialog_id: int, vtable: int, target: int, store: bytes) -> int:
    """mov edx,id; lea rcx,[rsp+40h]; call target; lea rax,[rip+vtable]; <store: mov [mem], rax>; ret."""
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    head = b"\xba" + struct.pack("<I", dialog_id) + b"\x48\x8d\x4c\x24\x40"
    call = b"\xe8" + struct.pack("<i", target - (va + len(head) + 5))
    lea_at = va + len(head) + len(call)
    lea = b"\x48\x8d\x05" + struct.pack("<i", vtable - (lea_at + 7))
    return b.code(head + call + lea + store + b"\xc3")


def test_ctor_dialogs_32bit_stack_objects():
    b = Builder(4)
    base = b.stub()
    vts = [b.vtable(None, [b.stub()]) for _ in range(5)]
    stores = [b"\xc7\x44\x24\x14",                       # mov dword [esp+14h], vtable   (SIB, disp8)
              b"\xc7\x45\xf8",                           # mov dword [ebp-8], vtable     (disp8)
              b"\xc7\x86\x00\x01\x00\x00",               # mov dword [esi+100h], vtable  (disp32)
              b"\xc7\x84\x24\x00\x02\x00\x00",           # mov dword [esp+200h], vtable  (SIB, disp32)
              b"\xc7\x05\x00\x00\x50\x00"]               # mov dword [500000h], vtable   (absolute: a global, no object)
    for k, (vt, st) in enumerate(zip(vts, stores)):
        raw_ctor32(b, 1000 + k, vt, base, st)
    got = mfc.ctor_dialogs(b.image(), vts, set(range(1000, 1005)))
    assert got == {vts[0]: 1000, vts[1]: 1001, vts[2]: 1002, vts[3]: 1003}


def test_ctor_dialogs_64bit_stack_objects():
    b = Builder(8)
    base = b.stub()
    vts = [b.vtable(None, [b.stub()]) for _ in range(6)]
    stores = [b"\x48\x89\x44\x24\x40",                   # mov [rsp+40h], rax   (SIB, disp8)
              b"\x48\x89\x45\xe8",                       # mov [rbp-18h], rax   (disp8)
              b"\x48\x89\x85\x00\x01\x00\x00",           # mov [rbp+100h], rax  (disp32)
              b"\x49\x89\x46\x08",                       # mov [r14+8], rax     (REX.B, disp8)
              b"\x48\x89\x05\x10\x00\x00\x00",           # mov [rip+10h], rax   (a global, no object)
              b"\x48\x89\xc3"]                           # mov rbx, rax         (register, no store)
    for k, (vt, st) in enumerate(zip(vts, stores)):
        raw_ctor64(b, 1000 + k, vt, base, st)
    got = mfc.ctor_dialogs(b.image(), vts, set(range(1000, 1006)))
    assert got == {vts[0]: 1000, vts[1]: 1001, vts[2]: 1002, vts[3]: 1003}


def build_shared(ps: int):
    """Shared MFC: dialog classes A, E, B in one run of code pointers, no CRuntimeClass of their own (the slot
    0 thunk goes into the DLL). A and B have a map at slot 8; E has none (it inherits the DLL's); F is a
    frame class with a map and no constructor that passes a dialog; G is a dialog class whose constructor
    is not seen (its map ids are the controls of one dialog, which alone does not name it)."""
    b = Builder(ps)
    h = b.stub()
    map_a = b.msgmap([(WM_COMMAND, 0, 5001, 5001, 12, h)])
    map_b = b.msgmap([(WM_COMMAND, 0, 5002, 5002, 12, h), (0x113, 0, 0, 0, 40, h)])
    map_f = b.msgmap([(WM_COMMAND, 0, 40001, 40001, 12, h)])
    map_g = b.msgmap([(WM_COMMAND, 0, 5003, 5003, 12, h), (WM_COMMAND, 0, 5004, 5004, 12, h)])
    ga, gb, gf, gg = (b.getter(m) for m in (map_a, map_b, map_f, map_g))
    thunk = b.stub()

    def slots(getter: int | None) -> list[int]:
        return [thunk] + [b.stub() for _ in range(7)] + [getter if getter else thunk] + [b.stub() for _ in range(3)]

    runs = slots(ga) + slots(None) + slots(gb)
    first = b.data(b"".join(b.ptr(x) for x in runs))
    vt_a, vt_e, vt_b = (first + k * 12 * ps for k in range(3))
    b.vtable(None, slots(gf))
    b.vtable(None, slots(gg))
    base = b.stub()
    mk = dialog_ctor if ps == 4 else dialog_ctor64
    mk(b, 1000, vt_a, base)
    mk(b, 1001, vt_b, base)
    mk(b, 1003, vt_e, base)
    return b, dict(map_a=map_a, map_b=map_b, map_f=map_f, map_g=map_g, vt_a=vt_a, vt_b=vt_b)


@pytest.mark.parametrize("ps", [4, 8], ids=["x86", "x64"])
def test_shared_mfc_dialog_classes_are_named(monkeypatch, ps):
    monkeypatch.setattr(mfc, "_dialog_ids", lambda path: {1000: "Alpha", 1001: "Beta", 1002: "Gamma", 1003: "Eps"})
    monkeypatch.setattr(mfc, "_dialog_ctrls", lambda path: {1000: {5001}, 1001: {5002}, 1002: {5003, 5004}})
    b, a = build_shared(ps)
    img = b.image()
    classes, slots, maps = cpp.parse_image(img)
    assert not classes and not mfc.find_runtime_classes(img)
    res = mfc.analyse(img, classes, slots, maps, None)
    by_addr = {m.map_addr: m.cls for m in maps}
    assert by_addr[a["map_a"]] == "Dialog_Alpha" and by_addr[a["map_b"]] == "Dialog_Beta"
    assert by_addr[a["map_g"]].startswith("anon_")                      # no constructor seen: control ids alone do not name it
    assert by_addr[a["map_f"]].startswith("anon_")                      # no dialog
    rows = {c.name: c for c in res.classes}
    assert (rows["Dialog_Alpha"].vtable, rows["Dialog_Alpha"].dialog, rows["Dialog_Alpha"].source) == \
        (a["vt_a"], "1000", "dialog")
    assert (rows["Dialog_Beta"].vtable, rows["Dialog_Beta"].map_addr) == (a["vt_b"], a["map_b"])
    assert "Dialog_Eps" not in rows and len(rows) == 2                  # E: the next getter is B's, wrong distance


def test_shared_mfc_needs_dialog_resources(monkeypatch):
    monkeypatch.setattr(mfc, "_dialog_ids", lambda path: {})
    b, a = build_shared(8)
    img = b.image()
    classes, slots, maps = cpp.parse_image(img)
    res = mfc.analyse(img, classes, slots, maps, None)
    assert all(m.cls.startswith("anon_") for m in maps) and not res.classes


def test_constructor_dialog_decides_the_class_dialog(proj):  # noqa: F811
    """A dialog class that also handles a menu id (a shared command) looks like a frame by its ids; the dialog
    id its constructor passed (``mfc_class.dialog``) decides."""
    ctx, st, bid, h = proj
    assert uijoin.UiIndex(st, bid).class_dialogs("CMainFrame") == []
    st.db.execute("INSERT INTO mfc_class(binary_id, name, vtable_addr, rc_addr, obj_size, schema, base, map_addr, "
                  "dialog, source) VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (bid, "CMainFrame", 0x1000, 0, 0, 0, "", 0, "102", "dialog"))
    st.db.commit()
    ui = uijoin.UiIndex(st, bid)
    assert ui.class_dialogs("CMainFrame") == ["102"] and ui.class_dialogs("CSettingsDlg") == ["101"]
    assert ui.class_dialog_text("CMainFrame").startswith("dialog 102")


@pytest.mark.parametrize("ps", [4, 8], ids=["x86", "x64"])
def test_connection_map_without_interface_getter_behind_it(ps):
    """Shared MFC: the class inherits ``GetInterfaceMap`` (a thunk into the DLL, no getter), so its connection map
    at slot 15 is alone; the slot number tells it from an interface map."""
    b = Builder(ps)
    conn = intmap(b, [(PROP_NOTIFY, 0x30)])
    lone = intmap(b, [(IDISPATCH, 16)])
    thunk = b.stub()

    def vt(slot: int, m: int, name: str) -> list[int]:
        s = [thunk] * 18
        s[0] = b.getter(runtime_class(b, name, 80))
        s[slot] = b.getter(m)
        return s

    b.vtable(None, vt(15, conn, "CSlot15"))
    b.vtable(None, vt(16, lone, "CSlot16"))                    # GetInterfaceMap: stays an interface map
    img = b.image()
    classes, slots, maps = cpp.parse_image(img)
    res = mfc.analyse(img, classes, slots, maps, None)
    got = sorted((m.cls, m.kind, m.addr) for m in res.maps)
    assert got == [("CSlot15", "connection", conn), ("CSlot16", "interface", lone)]
