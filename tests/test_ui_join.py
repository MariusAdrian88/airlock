"""M2 acceptance: MFC message maps joined with menus and dialogs, end to end through the tools.

One synthetic 32-bit PE (.text + .rdata with RTTI and message maps + .rsrc with a MENU and DIALOGs).
All names, captions and ids are invented."""

from __future__ import annotations

import struct

import pytest

from airlock.server import cpp, features as fx, peres, projectmap, uijoin
from airlock.server.tools import core, cpp as cpp_tools, resources as rt
from test_cpp import UPDATE_UI, WM_COMMAND, WM_NOTIFY, Builder
from test_resources import VIS, ctl, dlg_template, menu_template, rsrc_blob
from test_tools import make_ctx

EN_CHANGE = 0x300
NM_CLICK = 0xFFFFFFFE


def _pe(path, b: Builder, res) -> None:
    """PE32 with .text at 0x1000, .rdata at 0x3000 and .rsrc at 0x8000."""
    text = bytes(b.text).ljust(0x1000, b"\xcc")
    rdata = bytes(b.rd).ljust(0x4000, b"\0")
    rsrc = rsrc_blob(res, 0x8000)
    rsrc_raw = rsrc.ljust((len(rsrc) + 0x1FF) & ~0x1FF, b"\0")
    opt = struct.pack("<HBBIIIII", 0x10B, 0, 0, len(text), len(rdata) + len(rsrc), 0, 0, 0x1000)
    opt += struct.pack("<II", 0x3000, 0x400000) + struct.pack("<II", 0x1000, 0x200)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<IIII", 0, 0x8000 + ((len(rsrc) + 0xFFF) & ~0xFFF), 0x200, 0)
    opt += struct.pack("<HH", 3, 0) + struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\0" * 16 + struct.pack("<II", 0x8000, len(rsrc)) + b"\0" * (13 * 8)
    assert len(opt) == 0xE0
    coff = struct.pack("<HHIIIHH", 0x14C, 3, 0, 0, 0, len(opt), 0x2102)
    off = 0x200
    sects = b""
    for name, va, data, ch, vsize in ((b".text", 0x1000, text, 0x60000020, len(text)),
                                      (b".rdata", 0x3000, rdata, 0x40000040, len(rdata)),
                                      (b".rsrc", 0x8000, rsrc_raw, 0x40000040, len(rsrc))):
        sects += struct.pack("<8sIIIIIIHHI", name, vsize, va, len(data), off, 0, 0, 0, 0, ch)
        off += len(data)
    hdr = (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + sects).ljust(0x200, b"\0")
    path.write_bytes(hdr + text + rdata + rsrc_raw)


def _cls(b: Builder, mangled: str, getter: int, bases: list[str] | None = None) -> int:
    td = b.td(mangled)
    chd = b.chd([(td, 0)])
    return b.vtable(b.col(td, chd), [b.stub(), getter])


def _btn(cid, text, style=0):
    return ctl(VIS | 0x10000 | style, cid, 0x80, text)


def build_pe(path) -> dict[str, int]:
    """Menu 128 (File > Open..., Recent > One, Exit; Help > About), dialogs 101 (settings), 102 (other),
    103 (OK only); classes CMainFrame, CSettingsDlg, COtherDlg, CLonelyDlg (RTTI) and one without RTTI."""
    b = Builder(4)
    h = {n: b.stub() for n in ("open", "upd", "range", "ok", "browse", "chg", "ok2", "run", "ok3", "help")}
    maps = {
        "frame": b.msgmap([(WM_COMMAND, 0, 100, 100, 12, h["open"]),
                           (WM_COMMAND, UPDATE_UI, 100, 100, 66, h["upd"]),
                           (WM_COMMAND, 0, 101, 110, 12, h["range"])]),
        "settings": b.msgmap([(WM_COMMAND, 0, 1, 1, 12, h["ok"]), (WM_COMMAND, 0, 1000, 1000, 12, h["browse"]),
                              (WM_COMMAND, EN_CHANGE, 1001, 1001, 13, h["chg"])]),
        "other": b.msgmap([(WM_COMMAND, 0, 1, 1, 12, h["ok2"]), (WM_COMMAND, 0, 1010, 1010, 12, h["run"])]),
        "lonely": b.msgmap([(WM_COMMAND, 0, 1, 1, 12, h["ok3"])]),
        "anon": b.msgmap([(WM_COMMAND, 0, 1020, 1020, 12, h["help"])]),
    }
    g = {k: b.getter(v) for k, v in maps.items()}
    _cls(b, ".?AVCMainFrame@@", g["frame"])
    _cls(b, ".?AVCSettingsDlg@@", g["settings"])
    _cls(b, ".?AVCOtherDlg@@", g["other"])
    _cls(b, ".?AVCLonelyDlg@@", g["lonely"])
    b.vtable(None, [b.stub(), g["anon"]])
    res = {
        (4, 128, 0x409): menu_template(),
        (5, 101, 0x409): dlg_template("Settings", [
            _btn(1, "OK", 1), _btn(2, "Cancel"), _btn(1000, "&Browse..."),
            ctl(VIS | 0x10000 | 0x80, 1001, 0x81, ""), ctl(VIS | 3, 1002, 0x85, "")]),
        (5, 102, 0x409): dlg_template("Other", [_btn(1, "OK", 1), _btn(2, "Cancel"), _btn(1010, "Run"),
                                                _btn(1020, "Help")]),
        (5, 103, 0x409): dlg_template("Third", [_btn(1, "OK", 1)]),
    }
    _pe(path, b, res)
    return h


@pytest.fixture
def proj(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "ab" * 32
    h = build_pe(art / sha)
    bid = st.upsert_binary(sha, "app.exe", format="pe32", arch="x86", pointer_size=4,
                           image_base=0x400000, toolchain="msvc", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    b = st.get_binary_by_id(bid)
    assert peres.ensure(st, b, art / sha) and cpp.ensure(st, b, art / sha)   # as when a binary becomes ready
    names = {"open": ("CMainFrame", "OnFileOpen"), "upd": ("CMainFrame", "OnUpdateFileOpen"),
             "range": ("CMainFrame", "OnMru"), "ok": ("CSettingsDlg", "OnOK"),
             "browse": ("CSettingsDlg", "OnBrowse"), "chg": ("CSettingsDlg", "OnChange"),
             "ok2": ("COtherDlg", "OnOK"), "run": ("COtherDlg", "OnRun"), "ok3": ("CLonelyDlg", "OnOK"),
             "help": (None, "DoHelp")}
    st.insert_functions(bid, [{"entry": h[k], "name": n, "name_state": "auto", "namespace": ns, "size": 3}
                              for k, (ns, n) in names.items()])
    return ctx, st, bid, h


def lines_of(text: str) -> list[str]:
    return text.splitlines()


def test_menu_items_to_handlers(proj):
    ctx, st, bid, h = proj
    out = lines_of(rt.menus(ctx, "128"))
    open_line = next(ln for ln in out if "File > Open..." in ln)
    assert open_line.endswith("-> CMainFrame::OnFileOpen; update -> CMainFrame::OnUpdateFileOpen")
    assert next(ln for ln in out if "File > Exit" in ln).endswith("-> CMainFrame::OnMru")
    assert any("File > Recent > One" in ln and ln.endswith("-> CMainFrame::OnMru") for ln in out)
    about = next(ln for ln in out if "Help > About" in ln)
    assert "->" not in about                                    # nothing handles it


def test_dialog_buttons_to_handlers(proj):
    ctx, st, bid, h = proj
    out = lines_of(rt.dialogs(ctx, "101"))
    assert out[0].endswith("class CSettingsDlg")
    assert any(ln.startswith('  id=1000 Button "&Browse..."') and ln.endswith("-> BN_CLICKED CSettingsDlg::OnBrowse")
               for ln in out)
    assert any(ln.startswith("  id=1001 Edit") and ln.endswith("-> EN_CHANGE CSettingsDlg::OnChange") for ln in out)
    # IDOK in the settings dialog: only its own class, not the other classes that also handle id 1
    ok = next(ln for ln in out if ln.startswith('  id=1 Button "OK"'))
    assert ok.endswith("-> BN_CLICKED CSettingsDlg::OnOK")
    # a dialog without a linked class lists every handler of the shared id
    ok3 = next(ln for ln in lines_of(rt.dialogs(ctx, "103")) if ln.startswith("  id=1 "))
    assert ok3.endswith("-> BN_CLICKED CSettingsDlg::OnOK, BN_CLICKED COtherDlg::OnOK, BN_CLICKED CLonelyDlg::OnOK")
    # no-RTTI class: function name only
    help_ln = next(ln for ln in lines_of(rt.dialogs(ctx, "102")) if ln.startswith('  id=1020 '))
    assert help_ln.endswith("-> BN_CLICKED DoHelp")


def test_dialog_class_link(proj):
    ctx, st, bid, h = proj
    ui = uijoin.UiIndex(st, bid)
    assert ui.class_dialogs("CSettingsDlg") == ["101"]
    assert ui.class_dialogs("COtherDlg") == ["102"]
    assert ui.class_dialogs("CLonelyDlg") == []          # handles only IDOK: it must not decide alone
    assert ui.class_dialogs("CMainFrame") == []          # menu ids
    listing = lines_of(rt.dialogs(ctx))
    assert next(ln for ln in listing if ln.startswith("101 |")).endswith("| class CSettingsDlg")
    assert next(ln for ln in listing if ln.startswith("102 |")).split("| class ")[1].startswith("COtherDlg")
    assert "class" not in next(ln for ln in listing if ln.startswith("103 |"))


def test_message_maps_show_the_ui(proj):
    ctx, st, bid, h = proj
    frame = lines_of(cpp_tools.mfc_message_maps(ctx, "CMainFrame"))
    assert frame[1].endswith('CMainFrame::OnFileOpen  // menu "File > Open..."')
    assert frame[2].startswith("UPDATE_COMMAND_UI id 100 ") and frame[2].endswith('// menu "File > Open..."')
    assert frame[3].startswith("WM_COMMAND id 101-110 ") and \
        frame[3].endswith('// menu "File > Exit", menu "File > Recent > One"')
    dlg = lines_of(cpp_tools.mfc_message_maps(ctx, "CSettingsDlg"))
    assert dlg[0].endswith('entries 3 dialog 101 "Settings"')
    assert dlg[1].endswith('// dialog 101 button "OK"')
    assert dlg[2].endswith('// dialog 101 button "Browse..."')
    assert dlg[3].startswith("COMMAND id 1001") or "id 1001" in dlg[3]
    lonely = lines_of(cpp_tools.mfc_message_maps(ctx, "CLonelyDlg"))
    assert "dialog" not in lonely[0]
    assert lonely[1].endswith('// dialog 101 button "OK", dialog 102 button "OK", dialog 103 button "OK"')
    summary = lines_of(cpp_tools.mfc_message_maps(ctx))
    assert any(ln.startswith("CSettingsDlg map ") and ln.endswith('dialog 101 "Settings"') for ln in summary)


def test_function_hints(proj):
    ctx, st, bid, h = proj
    def sig(k):
        return core.function(ctx, f"0x{h[k]:x}", view="signature")
    assert 'handler for menu "File > Open..."' in sig("open")
    assert 'update handler for menu "File > Open..."' in sig("upd")
    assert 'handler for menu "File > Exit", menu "File > Recent > One"' in sig("range")
    assert 'handler for button "Browse..." in dialog 101' in sig("browse")
    assert "handler for edit id=1001 in dialog 101 (EN_CHANGE)" in sig("chg")
    assert 'handler for button "OK" in dialog 101' in sig("ok")


def test_features_get_resource_evidence(proj):
    ctx, st, bid, h = proj
    fx.derive(st)
    menu = {r["entry"]: r for r in st.feature_entries("ui-menu")}
    assert h["open"] in menu and 'menu "File > Open..."' in menu[h["open"]]["evidence"]
    assert menu[h["open"]]["depth"] == 0 and h["upd"] not in menu
    dlg = {r["entry"]: r for r in st.feature_entries("ui-dialog")}
    assert 'dialog 101 button "Browse..."' in dlg[h["browse"]]["evidence"]
    assert 'dialog 101 edit id=1001' in dlg[h["chg"]]["evidence"]
    assert h["ok3"] not in dlg            # a class that handles only IDOK cannot name its dialog
    assert fx.FEATURES_VERSION >= 4


def test_project_map_ui_line(proj):
    ctx, st, bid, h = proj
    s = uijoin.UiIndex(st, bid).summary()
    assert s == {"dialogs": 3, "menus": 1, "menu_items": 3, "controls": 7, "buttons": 6, "handlers": 8}
    assert uijoin.ui_line(st, bid) == ("UI: 3 dialogs, 1 menus; handlers mapped: 3 menu items, "
                                       "7 controls (6 buttons), 8 functions")
    pp = ctx.indexer.paths("proj")
    lines = projectmap.binaries_lines(pp, st, projectmap.load_manifest(pp))
    assert any(ln.strip().startswith("UI: 3 dialogs") for ln in lines)


def test_binary_without_resources_has_no_ui_line(tmp_path):
    from airlock.index.store import Store
    st = Store(tmp_path / "i.sqlite")
    bid = st.upsert_binary("dd" * 32, "x.exe", pointer_size=4)
    assert uijoin.ui_line(st, bid) == ""
    assert uijoin.function_hints(st, bid, 0x401000) == []


def test_notification_names():
    n = uijoin.notification
    assert n("Button", WM_COMMAND, 0) == "BN_CLICKED"
    assert n("Edit", WM_COMMAND, 0x300) == "EN_CHANGE"
    assert n("ComboBox", WM_COMMAND, 1) == "CBN_SELCHANGE"
    assert n("ListBox", WM_COMMAND, 0xFFFFFFFF) == "UPDATE_COMMAND_UI"
    assert n("SysListView32", WM_NOTIFY, NM_CLICK) == "NM_CLICK"
    assert n("Edit", WM_COMMAND, 0) == "COMMAND"
    assert n("Button", WM_COMMAND, 0x77) == "code 0x77"
    assert cpp.entry_label(WM_NOTIFY, NM_CLICK) == "WM_NOTIFY NM_CLICK"


def test_framework_range_entries_are_not_shown_on_controls(proj):
    """ON_NOTIFY_EX_RANGE over 0..0xFFFF (tooltips) and runtime range handlers match every control id:
    hidden from control / menu lines and handler hints, still listed by mfc_message_maps."""
    ctx, st, bid, h = proj
    tip, chev, user_wide = 0x1900, 0x1910, 0x1920
    st.insert_functions(bid, [
        {"entry": tip, "name": "OnToolTipText", "name_state": "library", "namespace": "CFrameWnd", "size": 3},
        {"entry": chev, "name": "OnChevronPushed", "name_state": "library", "namespace": "CFrameWnd", "size": 3},
        {"entry": user_wide, "name": "OnAnyNotify", "name_state": "auto", "namespace": "CMainFrame", "size": 3}])
    rows = [("CFrameWnd", 0x9000, WM_NOTIFY, 0xFFFFFDEE, 0, 0xFFFF, tip),       # whole id space
            ("CFrameWnd", 0x9000, WM_NOTIFY, 0xFFFFFCB7, 1000, 1010, chev),     # narrow, but runtime handler
            ("CMainFrame", 0x9100, WM_NOTIFY, 0xFFFFFFFE, 0, 0xFFFF, user_wide),  # wide range, program code
            ("CMainFrame", 0x9100, WM_COMMAND, 0, 0, 0xFFFF, user_wide)]
    st.db.executemany("INSERT INTO msgmap_entry(binary_id, class, map_addr, message, code, ctrl_id, last_id, "
                      "sig, handler, seq) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      [(bid, c, m, msg, code, i, la, 0, hd, 50 + k) for k, (c, m, msg, code, i, la, hd) in
                       enumerate(rows)])
    st.db.commit()
    ui = uijoin.UiIndex(st, bid)
    assert [ui.name_of(x) for x in ui.ctrl_handlers(1000, "")] == ["CSettingsDlg::OnBrowse"]
    assert {x.addr for x in ui.handlers_for(1000)} >= {tip, chev, user_wide}      # the raw join still has them
    names = [ui.name_of(x) for x in ui.ctrl_handlers(1000, "101")]
    assert names == ["CSettingsDlg::OnBrowse"]
    dlg = rt.dialogs(ctx, "101")
    assert "OnToolTipText" not in dlg and "OnChevronPushed" not in dlg and "OnAnyNotify" not in dlg
    assert "CSettingsDlg::OnBrowse" in dlg
    menus = rt.menus(ctx, "128")
    assert "OnAnyNotify" not in menus and "OnToolTipText" not in menus
    assert 'handler for' not in " ".join(ui.handler_hints(tip) + ui.handler_hints(chev) + ui.handler_hints(user_wide))
    maps = cpp_tools.mfc_message_maps(ctx, "CFrameWnd")
    assert "OnToolTipText" in maps and "OnChevronPushed" in maps
