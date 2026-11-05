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


def disp_entries(b: Builder, entries: list[tuple], tail: tuple | None = None) -> int:
    """entries: (name | None, dispid, params | None, vt, pfn, pfn_set, offset, flags)."""
    fmt = mfc._fmt(b.ps)
    allones = 2 ** (8 * b.ps) - 1
    raw = b""
    for name, did, params, vt, pfn, pfs, off, flags in entries + [(None, -1, None, 0xFF, 0, 0, allones, 0)]:
        n = b.data(name.encode() + b"\0", 1) if name is not None else 0
        pr = b.data(params + b"\0", 1) if params else 0
        raw += struct.pack(fmt, n, did, pr, vt, pfn, pfs, off, flags)
        if tail is not None:
            raw += struct.pack("<II", *(tail if name is not None else (0, 0)))
    return b.data(raw)


def dispmap(b: Builder, entries: list[tuple], base: int = 0) -> int:
    ents = disp_entries(b, entries)
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
    if b.ps == 4:
        assert by_addr[a["msg_dlg2"]] == "Dialog_About_Box"                     # dialog 1001 of the constructor
    else:
        assert by_addr[a["msg_dlg2"]] == f"anon_CDlg_{a['msg_dlg2']:0{w}x}"     # no constructor scan in 64-bit
    rows = {c.name: c for c in res.classes}
    assert rows["CFoo"].source == "rc" and rows["CFoo"].size == 100 and rows["CFoo"].rc == a["rc_foo"]
    assert rows["CDlg"].base == "CFoo"                                          # no base map: the base CRuntimeClass
    bar = rows[f"anon_CFoo_{a['msg_bar']:0{w}x}"]
    assert bar.source == "inherited" and bar.base == "CFoo" and bar.rc == 0 and bar.map_addr == a["msg_bar"]
    if b.ps == 4:
        assert rows["CDlg"].dialog == "1000" and rows["Dialog_About_Box"].dialog == "1001"
        assert rows["Dialog_About_Box"].base == "CDlg"


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


def test_names_helpers():
    assert mfc.ident("&Save As...") == "Save_As"
    assert mfc.ident("File\tCtrl+S") == "File"
    assert mfc.ident("a" * 40, 8) == "aaaaaaaa"
    assert mfc.vts_name(0x45) == "double&" and mfc.vts_name(0x4E) == "LPCSTR" and mfc.vts_name(8) == "BSTR"
    assert mfc.guid_name(IDISPATCH) == "IDispatch"
    assert mfc.guid_name(bytes(range(16))).startswith("{03020100-0504-0706-0809-0A0B0C0D0E0F")


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
