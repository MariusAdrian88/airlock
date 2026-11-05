"""PE resources on the server side (pefile, no Ghidra): dialogs, menus, string tables, version info.

``parse_file`` reads one PE file into plain rows; ``ensure`` fills the derived tables
``res_dialog``/``res_control``/``res_menu_item``/``res_string`` of a binary (schema v9) when they are
missing or were written by an older ``RESOURCES_VERSION``. The tables are a rebuildable cache.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pefile

from airlock.index.store import Binary, Store

log = logging.getLogger(__name__)

RESOURCES_VERSION = 1          # meta key ``resources_version:<binary id>``; older rows are parsed again
RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR",
            8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
            14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
            21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"}
RT_BY_NAME = {v: k for k, v in RT_NAMES.items()}
RT_MENU, RT_DIALOG, RT_STRING, RT_VERSION = 4, 5, 6, 16

CLASS_ATOMS = {0x80: "Button", 0x81: "Edit", 0x82: "Static", 0x83: "ListBox", 0x84: "ScrollBar",
               0x85: "ComboBox"}

_BS = {0: "BS_PUSHBUTTON", 1: "BS_DEFPUSHBUTTON", 2: "BS_CHECKBOX", 3: "BS_AUTOCHECKBOX",
       4: "BS_RADIOBUTTON", 5: "BS_3STATE", 6: "BS_AUTO3STATE", 7: "BS_GROUPBOX", 8: "BS_USERBUTTON",
       9: "BS_AUTORADIOBUTTON", 10: "BS_PUSHBOX", 11: "BS_OWNERDRAW"}
_SS = {0: "SS_LEFT", 1: "SS_CENTER", 2: "SS_RIGHT", 3: "SS_ICON", 4: "SS_BLACKRECT", 5: "SS_GRAYRECT",
       6: "SS_WHITERECT", 7: "SS_BLACKFRAME", 8: "SS_GRAYFRAME", 9: "SS_WHITEFRAME", 10: "SS_USERITEM",
       11: "SS_SIMPLE", 12: "SS_LEFTNOWORDWRAP", 13: "SS_OWNERDRAW", 14: "SS_BITMAP",
       15: "SS_ENHMETAFILE", 16: "SS_ETCHEDHORZ", 17: "SS_ETCHEDVERT", 18: "SS_ETCHEDFRAME"}
_CBS = {1: "CBS_SIMPLE", 2: "CBS_DROPDOWN", 3: "CBS_DROPDOWNLIST"}
_EDIT_BITS = ((0x4, "ES_MULTILINE"), (0x20, "ES_PASSWORD"), (0x800, "ES_READONLY"),
              (0x2000, "ES_NUMBER"), (0x1, "ES_CENTER"), (0x2, "ES_RIGHT"))
_LB_BITS = ((0x1, "LBS_NOTIFY"), (0x2, "LBS_SORT"), (0x8, "LBS_MULTIPLESEL"),
            (0x10, "LBS_OWNERDRAWFIXED"))
_CB_BITS = ((0x10, "CBS_OWNERDRAWFIXED"), (0x100, "CBS_SORT"))
WS_VISIBLE, WS_DISABLED, WS_GROUP, WS_TABSTOP = 0x10000000, 0x08000000, 0x00020000, 0x00010000
DS_SETFONT, DS_SHELLFONT = 0x40, 0x48
MF_POPUP, MF_END = 0x10, 0x80


@dataclass
class Ctrl:
    ctrl_id: int
    cls: str
    caption: str
    style: str


@dataclass
class Dialog:
    caption: str
    x: int
    y: int
    cx: int
    cy: int
    controls: list[Ctrl] = field(default_factory=list)


@dataclass
class MenuItem:
    item_id: int | None
    caption: str
    path: str


def clean_caption(text: str) -> str:
    """Menu caption without the accelerator hint (after TAB) and with ``&`` mnemonics removed."""
    text = text.split("\t", 1)[0]
    return text.replace("&&", "\0").replace("&", "").replace("\0", "&")


# -- dialogs ---------------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.d, self.p = data, pos

    def left(self) -> int:
        return len(self.d) - self.p

    def u(self, fmt: str) -> tuple[int, ...]:
        size = struct.calcsize("<" + fmt)
        if self.p + size > len(self.d):
            raise ValueError("truncated")
        out = struct.unpack_from("<" + fmt, self.d, self.p)
        self.p += size
        return out

    def align(self, n: int) -> None:
        self.p = (self.p + n - 1) & ~(n - 1)

    def wstr(self) -> str:
        end = self.p
        d = self.d
        while end + 1 < len(d) and (d[end] or d[end + 1]):
            end += 2
        if end + 1 >= len(d):
            raise ValueError("unterminated string")
        s = d[self.p:end].decode("utf-16-le", "replace")
        self.p = end + 2
        return s

    def sz_or_ord(self) -> str | int | None:
        """None (absent), int (ordinal) or str."""
        (w,) = self.u("H")
        if w == 0:
            return None
        if w == 0xFFFF:
            return self.u("H")[0]
        self.p -= 2
        return self.wstr()


def _style_words(cls: str, style: int) -> str:
    words: list[str] = []
    low = cls.lower()
    if low == "button":
        words.append(_BS.get(style & 0xF, f"BS_{style & 0xF:#x}"))
    elif low == "static":
        words.append(_SS.get(style & 0x1F, f"SS_{style & 0x1F:#x}"))
    elif low == "edit":
        words += [n for bit, n in _EDIT_BITS if style & bit]
    elif low == "listbox":
        words += [n for bit, n in _LB_BITS if style & bit]
    elif low == "combobox":
        words.append(_CBS.get(style & 0x3, f"CBS_{style & 0x3:#x}"))
        words += [n for bit, n in _CB_BITS if style & bit]
    if not style & WS_VISIBLE:
        words.append("hidden")
    if style & WS_DISABLED:
        words.append("disabled")
    if style & WS_TABSTOP:
        words.append("tabstop")
    if style & WS_GROUP:
        words.append("group")
    return ",".join(words)


def _signed(v: int, bits: int) -> int:
    return v - (1 << bits) if v >= 1 << (bits - 1) else v


def parse_dialog(data: bytes) -> Dialog:
    """DLGTEMPLATE or DLGTEMPLATEEX; raises ValueError when malformed."""
    r = _Reader(data)
    ver, sig = struct.unpack_from("<HH", data, 0) if len(data) >= 4 else (0, 0)
    ex = ver == 1 and sig == 0xFFFF
    if ex:
        r.p = 4
        _help, _exstyle, style = r.u("III")
        (n,) = r.u("H")
    else:
        style, _exstyle = r.u("II")
        (n,) = r.u("H")
    x, y, cx, cy = (_signed(v, 16) for v in r.u("HHHH"))
    r.sz_or_ord()                                   # menu
    r.sz_or_ord()                                   # window class
    title = r.sz_or_ord()
    caption = title if isinstance(title, str) else ""
    if style & DS_SETFONT:
        r.u("H")
        if ex:
            r.u("HBB")
        r.wstr()
    dlg = Dialog(caption, x, y, cx, cy)
    for _ in range(n):
        r.align(4)
        if r.left() < 20:
            break
        if ex:
            _h, _es, st = r.u("III")
            r.u("hhhh")
            (cid,) = r.u("I")
            cid = _signed(cid, 32)
        else:
            st, _es = r.u("II")
            r.u("hhhh")
            (cid,) = r.u("H")
            cid = _signed(cid, 16)
        c = r.sz_or_ord()
        if isinstance(c, int):
            cls = CLASS_ATOMS.get(c, f"#{c:#x}")
        else:
            cls = c or ""
        t = r.sz_or_ord()
        text = t if isinstance(t, str) else (f"#{t}" if isinstance(t, int) else "")
        (extra,) = r.u("H")
        r.p += extra
        dlg.controls.append(Ctrl(cid, cls, text, _style_words(cls, st)))
    return dlg


# -- menus -----------------------------------------------------------------------------------

def parse_menu(data: bytes) -> list[MenuItem]:
    """MENU or MENUEX template as a flat list in order; popups have ``item_id`` None."""
    r = _Reader(data)
    ver, off = r.u("HH")
    out: list[MenuItem] = []
    if ver == 1:                                    # MENUEX
        r.p = 4 + off
        _items_ex(r, [], out)
    else:
        r.p = 4 + off
        _items(r, [], out)
    return out


def _items(r: _Reader, trail: list[str], out: list[MenuItem]) -> None:
    while r.left() >= 4:
        (flags,) = r.u("H")
        if flags & MF_POPUP:
            text = clean_caption(r.wstr())
            out.append(MenuItem(None, text, " > ".join([*trail, text])))
            _items(r, [*trail, text], out)
        else:
            (iid,) = r.u("H")
            text = clean_caption(r.wstr())
            if iid or text:                         # a separator has id 0 and no text
                out.append(MenuItem(iid, text, " > ".join([*trail, text])))
        if flags & MF_END:
            return


def _items_ex(r: _Reader, trail: list[str], out: list[MenuItem]) -> None:
    while r.left() >= 16:
        r.align(4)
        typ, _state, iid, res = r.u("IIIH")
        text = clean_caption(r.wstr())
        r.align(4)
        if res & 0x1:
            r.u("I")                                # help id
            out.append(MenuItem(None, text, " > ".join([*trail, text])))
            _items_ex(r, [*trail, text], out)
        elif not typ & 0x800 or text:               # MFT_SEPARATOR is 0x800
            out.append(MenuItem(iid, text, " > ".join([*trail, text])))
        if res & MF_END:
            return


# -- strings ---------------------------------------------------------------------------------

def parse_string_block(data: bytes, block: int) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    p = 0
    for i in range(16):
        if p + 2 > len(data):
            break
        (n,) = struct.unpack_from("<H", data, p)
        p += 2
        if n:
            out.append(((block - 1) * 16 + i, data[p:p + 2 * n].decode("utf-16-le", "replace")))
        p += 2 * n
    return out


# -- file level ------------------------------------------------------------------------------

@dataclass
class ResEntry:
    type_id: int | None
    type_name: str
    res_id: int | None
    res_name: str | None
    lang: int
    rva: int
    size: int

    @property
    def key(self) -> str:
        return str(self.res_id) if self.res_name is None else self.res_name


@dataclass
class Parsed:
    entries: list[ResEntry] = field(default_factory=list)
    dialogs: list[tuple[str, int, Dialog]] = field(default_factory=list)
    menus: list[tuple[str, int, list[MenuItem]]] = field(default_factory=list)
    strings: list[tuple[int, int, str]] = field(default_factory=list)      # (id, lang, text)


def _name(entry: Any) -> str | None:
    n = getattr(entry, "name", None)
    if n is None:
        return None
    return n.decode("utf-16-le", "replace") if isinstance(n, bytes) else str(n)


def list_entries(pe: pefile.PE) -> list[ResEntry]:
    top = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    out: list[ResEntry] = []
    if top is None:
        return out
    for t in top.entries:
        tname = _name(t)
        tid = None if tname is not None else t.id
        label = tname if tname is not None else RT_NAMES.get(t.id, str(t.id))
        for n in getattr(getattr(t, "directory", None), "entries", ()):
            nname = _name(n)
            for lg in getattr(getattr(n, "directory", None), "entries", ()):
                d = getattr(lg, "data", None)
                if d is None:
                    continue
                out.append(ResEntry(tid, label, None if nname is not None else n.id, nname,
                                    int(lg.id or 0), int(d.struct.OffsetToData), int(d.struct.Size)))
    return out


def open_pe(path: Path) -> pefile.PE | None:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        return pe
    except (pefile.PEFormatError, OSError, ValueError, struct.error):
        return None


def parse_file(path: Path) -> Parsed | None:
    """Everything the tables hold. None when the file is not a PE; unreadable resources are skipped."""
    pe = open_pe(path)
    if pe is None:
        return None
    try:
        res = Parsed(entries=list_entries(pe))
        for e in res.entries:
            if e.type_id not in (RT_MENU, RT_DIALOG, RT_STRING):
                continue
            try:
                data = pe.get_data(e.rva, e.size)
                if e.type_id == RT_DIALOG:
                    res.dialogs.append((e.key, e.lang, parse_dialog(data)))
                elif e.type_id == RT_MENU:
                    res.menus.append((e.key, e.lang, parse_menu(data)))
                elif e.res_id:
                    res.strings += [(i, e.lang, s) for i, s in parse_string_block(data, e.res_id)]
            except (ValueError, struct.error, pefile.PEFormatError) as ex:
                log.debug("resource %s %s unreadable: %s", e.type_name, e.key, ex)
        return res
    finally:
        pe.close()


def version_info(path: Path) -> list[str] | None:
    """Lines ``key: value`` from the VS_VERSION_INFO resource; None when absent or not a PE."""
    pe = open_pe(path)
    if pe is None:
        return None
    try:
        ent = next((e for e in list_entries(pe) if e.type_id == RT_VERSION), None)
        if ent is None:
            return None
        data = pe.get_data(ent.rva, ent.size)
        return _version_lines(data)
    except (ValueError, struct.error, pefile.PEFormatError):
        return None
    finally:
        pe.close()


def _version_lines(data: bytes) -> list[str]:
    out: list[str] = []
    sig = data.find(b"\xbd\x04\xef\xfe")
    if sig >= 0 and sig + 52 <= len(data):
        v = struct.unpack_from("<13I", data, sig)
        fv = f"{v[2] >> 16}.{v[2] & 0xFFFF}.{v[3] >> 16}.{v[3] & 0xFFFF}"
        pv = f"{v[4] >> 16}.{v[4] & 0xFFFF}.{v[5] >> 16}.{v[5] & 0xFFFF}"
        out += [f"FileVersion (fixed): {fv}", f"ProductVersion (fixed): {pv}"]
    # StringFileInfo: walk the VS_VERSIONINFO children by their length fields
    start = data.find("StringFileInfo".encode("utf-16-le"))
    if start >= 6:
        _walk_strings(data, start - 6, out)
    return out


def _walk_strings(data: bytes, p: int, out: list[str]) -> None:
    """StringFileInfo block at ``p``: StringTable blocks of String blocks."""
    r = _Reader(data, p)
    length, _vl, _ty = r.u("HHH")
    end = min(len(data), p + length)
    r.wstr()
    while True:
        r.align(4)
        if r.p + 6 > end:
            return
        t_start = r.p
        tl, _tv, _tt = r.u("HHH")
        if tl < 6:
            return
        t_end = min(end, t_start + tl)
        lang = r.wstr()
        out.append(f"language: {lang}")
        while True:
            r.align(4)
            if r.p + 6 > t_end:
                break
            s_start = r.p
            sl, svl, _st = r.u("HHH")
            if sl == 0:
                break
            key = r.wstr()
            r.align(4)
            val = ""
            if svl:
                try:
                    val = r.wstr()
                except ValueError:
                    val = ""
            r.p = s_start + sl
            if val:
                out.append(f"{key}: {val}")
        r.p = t_end


# -- tables ----------------------------------------------------------------------------------

def _meta_key(bid: int) -> str:
    return f"resources_version:{bid}"


def stale(store: Store, bid: int) -> bool:
    return store.get_meta(_meta_key(bid)) != str(RESOURCES_VERSION)


def ensure(store: Store, b: Binary, artifact: Path, force: bool = False) -> bool:
    """Fill the resource tables of binary ``b`` from its stored file when missing or stale.
    True when it parsed now. A file that is not a PE gets no rows and is not parsed again."""
    if not force and not stale(store, b.id):
        return False
    if not artifact.is_file():
        return False
    parsed = parse_file(artifact)
    db = store.db
    with db:
        for t in ("res_dialog", "res_control", "res_menu_item", "res_string"):
            db.execute(f"DELETE FROM {t} WHERE binary_id=?", (b.id,))
        if parsed is not None:
            for key, lang, d in parsed.dialogs:
                db.execute("INSERT OR REPLACE INTO res_dialog VALUES (?,?,?,?,?,?,?,?)",
                           (b.id, key, lang, d.caption, d.x, d.y, d.cx, d.cy))
                db.executemany(
                    "INSERT INTO res_control VALUES (?,?,?,?,?,?,?,?)",
                    [(b.id, key, lang, c.ctrl_id, c.cls, c.caption, c.style, i)
                     for i, c in enumerate(d.controls)])
            for key, lang, items in parsed.menus:
                db.executemany(
                    "INSERT INTO res_menu_item VALUES (?,?,?,?,?,?,?)",
                    [(b.id, key, lang, m.item_id, m.caption, m.path, i) for i, m in enumerate(items)])
            db.executemany("INSERT INTO res_string VALUES (?,?,?,?)",
                           [(b.id, i, lang, s) for i, lang, s in parsed.strings])
        store.set_meta(_meta_key(b.id), str(RESOURCES_VERSION))
    return True


def ensure_project(store: Store, artifacts: Path) -> int:
    """``ensure`` for every binary of the project; returns how many were parsed."""
    n = 0
    for b in store.list_binaries():
        try:
            n += ensure(store, b, artifacts / b.sha256)
        except Exception as e:  # noqa: BLE001  resources are an extra
            log.warning("resources of %s: %s", b.name, e)
    return n
