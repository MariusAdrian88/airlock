"""M2 join: MFC message map entries x PE resources (menu items, dialog controls).

Derived on demand from the tables ``msgmap_entry`` (server/cpp.py) and ``res_*`` (server/peres.py) of one
binary; nothing is stored. ``UiIndex`` answers: which handlers does a menu item / dialog control have,
which menu item or control does an id belong to, which dialog is a class's dialog, which UI element
does a handler serve. Names are hints: nothing is renamed in Ghidra.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from typing import Any

from airlock.index.store import Store
from airlock.server import cpp
from airlock.server.peres import clean_caption

WM_COMMAND, WM_NOTIFY = 0x111, 0x4E
UPDATE_UI = 0xFFFFFFFF
GENERIC_IDS = frozenset(range(1, 10))        # IDOK .. IDHELP: shared by most dialogs, never decide alone
STATIC_IDS = frozenset({0, 0xFFFF, 0xFFFFFFFF})
MAX_RANGE_SCAN = 4096                         # ids of one range entry looked at
MAX_LIST = 3                                  # items listed before "+N"
MAX_DIALOG_CANDIDATES = 3

_BN = {0: "BN_CLICKED", 1: "BN_PAINT", 2: "BN_HILITE", 3: "BN_UNHILITE", 4: "BN_DISABLE",
       5: "BN_DOUBLECLICKED", 6: "BN_SETFOCUS", 7: "BN_KILLFOCUS"}
_EN = {0x100: "EN_SETFOCUS", 0x200: "EN_KILLFOCUS", 0x300: "EN_CHANGE", 0x400: "EN_UPDATE",
       0x500: "EN_ERRSPACE", 0x501: "EN_MAXTEXT", 0x601: "EN_HSCROLL", 0x602: "EN_VSCROLL"}
_LBN = {1: "LBN_SELCHANGE", 2: "LBN_DBLCLK", 3: "LBN_SELCANCEL", 4: "LBN_SETFOCUS", 5: "LBN_KILLFOCUS"}
_CBN = {1: "CBN_SELCHANGE", 2: "CBN_DBLCLK", 3: "CBN_SETFOCUS", 4: "CBN_KILLFOCUS", 5: "CBN_EDITCHANGE",
        6: "CBN_EDITUPDATE", 7: "CBN_DROPDOWN", 8: "CBN_CLOSEUP", 9: "CBN_SELENDOK", 10: "CBN_SELENDCANCEL"}
_STN = {0: "STN_CLICKED", 1: "STN_DBLCLK", 2: "STN_ENABLE", 3: "STN_DISABLE"}
_BY_CLASS = {"button": _BN, "edit": _EN, "listbox": _LBN, "combobox": _CBN, "static": _STN}
_NOTIFY = {**cpp.NM_NAMES,
           0xFFFFFF9C: "LVN_ITEMCHANGING", 0xFFFFFF9B: "LVN_ITEMCHANGED", 0xFFFFFF94: "LVN_COLUMNCLICK",
           0xFFFFFF8E: "LVN_ITEMACTIVATE", 0xFFFFFF6A: "LVN_GETDISPINFO", 0xFFFFFE6E: "TVN_SELCHANGEDA",
           0xFFFFFE3D: "TVN_SELCHANGEDW", 0xFFFFFE6F: "TVN_SELCHANGINGA", 0xFFFFFE3E: "TVN_SELCHANGINGW",
           0xFFFFFDD9: "TCN_SELCHANGE", 0xFFFFFDD8: "TCN_SELCHANGING", 0xFFFFFD2E: "UDN_DELTAPOS",
           0xFFFFFD11: "DTN_DATETIMECHANGE"}


def notification(cls: str, message: int, code: int) -> str:
    """Notification name of a control entry: ``BN_CLICKED``, ``EN_CHANGE``, ``NM_CLICK``, ``UPDATE_COMMAND_UI``."""
    if message == WM_NOTIFY:
        return _NOTIFY.get(code, f"WM_NOTIFY 0x{code:x}") if code else "WM_NOTIFY"
    if code == UPDATE_UI:
        return "UPDATE_COMMAND_UI"
    k = cls.lower()
    table = _BY_CLASS.get(k)
    if code == 0:
        return table[0] if table and k in ("button", "static") else ("COMMAND" if table else "BN_CLICKED")
    if table and code in table:
        return table[code]
    if code in _EN and not table:
        return _EN[code]
    return cpp.CN_NAMES.get(code, f"code 0x{code:x}")


@dataclass(frozen=True)
class Handler:
    cls: str
    map_addr: int
    message: int
    code: int
    id: int
    last: int
    addr: int

    @property
    def is_update(self) -> bool:
        return self.message == WM_COMMAND and self.code == UPDATE_UI

    @property
    def is_command(self) -> bool:
        return self.message == WM_COMMAND and self.code == 0

    @property
    def span(self) -> tuple[int, int]:
        return self.id, max(self.id, self.last)


@dataclass(frozen=True)
class CtrlRef:
    dialog: str
    cls: str
    caption: str
    ctrl_id: int

    @property
    def kind(self) -> str:
        return (self.cls or "control").lower()

    def label(self) -> str:
        """``dialog 101 button "OK"`` (evidence form)."""
        what = f'"{self.caption}"' if self.caption else f"id={self.ctrl_id}"
        return f"dialog {self.dialog} {self.kind} {what}"

    def short(self) -> str:
        """``button "OK" in dialog 101`` (function hint form)."""
        what = f'"{self.caption}"' if self.caption else f"id={self.ctrl_id}"
        return f"{self.kind} {what} in dialog {self.dialog}"


def _compact(items: list[str], limit: int = MAX_LIST) -> str:
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" +{len(items) - limit}"


def _short_caption(text: str, n: int = 40) -> str:
    t = clean_caption(text or "").replace('"', "'").strip()
    return t if len(t) <= n else t[:n - 1] + "…"


class UiIndex:
    """Message map handlers and UI resources of one binary, joined on the control / command id."""

    def __init__(self, store: Store, binary_id: int) -> None:
        self.store = store
        self.bid = binary_id
        q = store.db.execute
        self.menu_refs: dict[int, list[str]] = {}
        for r in q("SELECT item_id, path FROM res_menu_item WHERE binary_id=? AND item_id IS NOT NULL "
                   "ORDER BY menu_id, lang, seq", (binary_id,)):
            if r["item_id"] > 0 and r["item_id"] not in STATIC_IDS:
                lst = self.menu_refs.setdefault(r["item_id"], [])
                p = _short_caption(r["path"], 80)
                if p not in lst:
                    lst.append(p)
        self.ctrl_refs: dict[int, list[CtrlRef]] = {}
        seen: set[tuple[str, int, str, str]] = set()
        for r in q("SELECT dialog_id, ctrl_id, class, caption FROM res_control WHERE binary_id=? "
                   "AND ctrl_id IS NOT NULL ORDER BY dialog_id, lang, seq", (binary_id,)):
            cid = r["ctrl_id"]
            if cid <= 0 or cid in STATIC_IDS:
                continue
            ref = CtrlRef(r["dialog_id"], r["class"] or "", _short_caption(r["caption"] or "", 40), cid)
            key = (ref.dialog, cid, ref.cls, ref.caption)
            if key not in seen:
                seen.add(key)
                self.ctrl_refs.setdefault(cid, []).append(ref)
        self.dialog_caption: dict[str, str] = {}
        for r in q("SELECT dialog_id, caption FROM res_dialog WHERE binary_id=? ORDER BY lang DESC", (binary_id,)):
            self.dialog_caption[r["dialog_id"]] = _short_caption(r["caption"] or "", 40)
        self.dialog_ids: dict[str, set[int]] = {}
        for cid, refs in self.ctrl_refs.items():
            for ref in refs:
                self.dialog_ids.setdefault(ref.dialog, set()).add(cid)
        self.handlers: list[Handler] = []
        self._single: dict[int, list[Handler]] = {}
        self._ranges: list[Handler] = []
        for r in q("SELECT class, map_addr, message, code, ctrl_id, last_id, handler FROM msgmap_entry "
                   "WHERE binary_id=? AND message IN (?,?) ORDER BY map_addr, seq",
                   (binary_id, WM_COMMAND, WM_NOTIFY)):
            h = Handler(r["class"], r["map_addr"], r["message"], r["code"], r["ctrl_id"], r["last_id"],
                        r["handler"])
            if h.id == 0 and h.last == 0:
                continue
            self.handlers.append(h)
            if h.last > h.id:
                self._ranges.append(h)
            else:
                self._single.setdefault(h.id, []).append(h)
        self._menu_keys = sorted(self.menu_refs)
        self._ctrl_keys = sorted(self.ctrl_refs)
        self._fn: dict[int, Any] = {}
        self._class_dialogs: dict[str, list[str]] = {}
        self._dialog_classes: dict[str, list[str]] | None = None

    # -- basics ----------------------------------------------------------------------------------

    @property
    def has_ui(self) -> bool:
        return bool(self.menu_refs or self.ctrl_refs)

    def handlers_for(self, ident: int) -> list[Handler]:
        out = list(self._single.get(ident, ()))
        out += [h for h in self._ranges if h.id <= ident <= h.last]
        return out

    def name_of(self, h: Handler, addr_fmt=lambda a: f"0x{a:08x}") -> str:
        """``Class::OnOpen``; the plain function name (or the address) for an ``anon_`` class."""
        if h.addr not in self._fn:
            self._fn[h.addr] = self.store.function_at(self.bid, h.addr)
        fn = self._fn[h.addr]
        if fn is None:
            return addr_fmt(h.addr)
        name = fn.qualified_name
        if h.cls.startswith(cpp.ANON_PREFIX) or "::" in name:
            return name
        return f"{h.cls}::{name}"

    def _ids_in(self, keys: list[int], lo: int, hi: int) -> list[int]:
        i = bisect_left(keys, lo)
        j = bisect_right(keys, hi)
        return keys[i:min(j, i + MAX_RANGE_SCAN)]

    # -- menus -----------------------------------------------------------------------------------

    def menu_handlers(self, item_id: int) -> tuple[list[Handler], list[Handler]]:
        """(command handlers, update-UI handlers) of a menu item id."""
        hs = self.handlers_for(item_id)
        return ([h for h in hs if h.is_command and h.message == WM_COMMAND],
                [h for h in hs if h.is_update])

    def menu_suffix(self, item_id: int) -> str:
        cmd, upd = self.menu_handlers(item_id)
        parts = []
        if cmd:
            parts.append("-> " + _compact(_uniq(self.name_of(h) for h in cmd)))
        if upd:
            parts.append("update -> " + _compact(_uniq(self.name_of(h) for h in upd)))
        return "; ".join(parts)

    # -- dialogs ---------------------------------------------------------------------------------

    def _handled_ids(self, cls: str) -> set[int]:
        out: set[int] = set()
        for h in self.handlers:
            if h.cls != cls:
                continue
            lo, hi = h.span
            if hi == lo:
                out.add(lo)
            else:
                out.update(self._ids_in(self._ctrl_keys, lo, hi))
                out.update(self._ids_in(self._menu_keys, lo, hi))
        return {i for i in out if i not in STATIC_IDS and i > 0}

    def class_dialogs(self, cls: str) -> list[str]:
        """Dialog ids that are the class's dialog: every id the class handles appears in the dialog
        (best effort; shared ids like IDOK never decide alone)."""
        if cls in self._class_dialogs:
            return self._class_dialogs[cls]
        res: list[str] = []
        ids = self._handled_ids(cls)
        if any(i in self.menu_refs and i not in self.ctrl_refs for i in ids):
            ids = set()                                   # a frame / view / document class
        present = [i for i in ids if i in self.ctrl_refs]
        if any(i not in GENERIC_IDS for i in present):
            cands: set[str] | None = None
            for i in present:
                ds = {r.dialog for r in self.ctrl_refs[i]}
                cands = ds if cands is None else cands & ds
            if cands and len(cands) <= MAX_DIALOG_CANDIDATES:
                res = sorted(cands, key=_dialog_key)
        self._class_dialogs[cls] = res
        return res

    def class_dialog_text(self, cls: str) -> str:
        """``dialog 101 "About"`` for the class's dialog(s); empty when there is none."""
        out = []
        for d in self.class_dialogs(cls):
            cap = self.dialog_caption.get(d, "")
            out.append(f'dialog {d} "{cap}"' if cap else f"dialog {d}")
        return _compact(out)

    def dialog_classes(self, dialog: str) -> list[str]:
        if self._dialog_classes is None:
            self._dialog_classes = {}
            for cls in sorted({h.cls for h in self.handlers}):
                for d in self.class_dialogs(cls):
                    self._dialog_classes.setdefault(d, []).append(cls)
        return self._dialog_classes.get(dialog, [])

    def ctrl_handlers(self, ctrl_id: int, dialog: str = "") -> list[Handler]:
        """Handlers of a dialog control id. With a dialog that has linked classes, only theirs (when they
        handle the id). A shared id (IDOK..IDHELP) that no linked class handles, or that more than
        MAX_LIST unlinked classes handle, gets none: it cannot be told apart."""
        hs = self.handlers_for(ctrl_id)
        if dialog:
            mine = set(self.dialog_classes(dialog))
            own = [h for h in hs if h.cls in mine]
            if own:
                return own
            if ctrl_id in GENERIC_IDS and (mine or len({h.cls for h in hs}) > MAX_LIST):
                return []
        return hs

    def ctrl_suffix(self, ref: CtrlRef) -> str:
        hs = self.ctrl_handlers(ref.ctrl_id, ref.dialog)
        if not hs:
            return ""
        items = _uniq(f"{notification(ref.cls, h.message, h.code)} {self.name_of(h)}" for h in hs)
        return "-> " + _compact(items)

    # -- ids to UI -------------------------------------------------------------------------------

    def refs_of(self, lo: int, hi: int = 0) -> tuple[list[str], list[CtrlRef]]:
        """Menu paths and dialog controls whose id lies in lo..hi."""
        hi = max(hi, lo)
        if hi == lo:
            return list(self.menu_refs.get(lo, ())), list(self.ctrl_refs.get(lo, ()))
        menus: list[str] = []
        ctrls: list[CtrlRef] = []
        for i in self._ids_in(self._menu_keys, lo, hi):
            menus += self.menu_refs[i]
        for i in self._ids_in(self._ctrl_keys, lo, hi):
            ctrls += self.ctrl_refs[i]
        return menus, ctrls

    def entry_note(self, h: Handler) -> str:
        """``menu "File > Open..."`` / ``dialog 101 button "OK"`` for a message map entry (compact)."""
        if h.message not in (WM_COMMAND, WM_NOTIFY):
            return ""
        menus, ctrls = self.refs_of(*h.span)
        if h.message == WM_NOTIFY:
            menus = []
        items = [f'menu "{m}"' for m in menus] + [c.label() for c in _prefer(ctrls, self.class_dialogs(h.cls))]
        return _compact(_uniq(items))

    # -- handler to UI ---------------------------------------------------------------------------

    def ui_of_handlers(self) -> dict[int, dict[str, list[str]]]:
        """{handler address: {"menu": [...], "dialog": [...], "update": [...]}} for non-empty ones;
        lists hold evidence strings (``menu "File > Open..."``, ``dialog 101 button "OK"``)."""
        out: dict[int, dict[str, list[str]]] = {}
        for h in self.handlers:
            menus, ctrls = self.refs_of(*h.span)
            if h.message == WM_NOTIFY:
                menus = []
            ctrls = _prefer(ctrls, self.class_dialogs(h.cls), strict=True)
            if not menus and not ctrls:
                continue
            d = out.setdefault(h.addr, {"menu": [], "dialog": [], "update": []})
            if h.is_update:
                d["update"] += [f'menu "{m}"' for m in menus] + [c.label() for c in ctrls]
            else:
                d["menu"] += [f'menu "{m}"' for m in menus]
                d["dialog"] += [c.label() for c in ctrls]
        for d in out.values():
            for k in d:
                d[k] = _uniq(d[k])
        return out

    def handler_hints(self, entry: int) -> list[str]:
        """Function hints: ``handler for menu "File > Open..."``, ``handler for button "OK" in dialog 101``."""
        menus: list[str] = []
        updates: list[str] = []
        ctrls: list[str] = []
        for h in self.handlers:
            if h.addr != entry:
                continue
            m, c = self.refs_of(*h.span)
            if h.message == WM_NOTIFY:
                m = []
            c = _prefer(c, self.class_dialogs(h.cls), strict=True)
            (updates if h.is_update else menus).extend(f'menu "{x}"' for x in m)
            if not h.is_update:
                for r in c:
                    n = notification(r.cls, h.message, h.code)
                    ctrls.append(r.short() if n in ("BN_CLICKED", "COMMAND", "STN_CLICKED")
                                 else f"{r.short()} ({n})")
        out = []
        if menus:
            out.append("handler for " + _compact(_uniq(menus)))
        if updates:
            out.append("update handler for " + _compact(_uniq(updates)))
        if ctrls:
            out.append("handler for " + _compact(_uniq(ctrls)))
        return out

    def summary(self) -> dict[str, int]:
        """Counts for the project map: dialogs, menus, menu items / controls / buttons with a handler,
        distinct handler functions mapped from the UI."""
        q = self.store.db.execute
        n_dlg = q("SELECT COUNT(DISTINCT dialog_id) FROM res_dialog WHERE binary_id=?", (self.bid,)).fetchone()[0]
        n_menu = q("SELECT COUNT(DISTINCT menu_id) FROM res_menu_item WHERE binary_id=?", (self.bid,)).fetchone()[0]
        items = {i for i in self.menu_refs if any(h.message == WM_COMMAND and not h.is_update
                                                  for h in self.handlers_for(i))}
        ctrls = {(r.dialog, r.ctrl_id, r.cls, r.caption) for refs in self.ctrl_refs.values() for r in refs
                 if self.ctrl_handlers(r.ctrl_id, r.dialog)}
        buttons = sum(1 for c in ctrls if c[2].lower() == "button")
        mapped = {a for a, d in self.ui_of_handlers().items() if d["menu"] or d["dialog"]}
        return {"dialogs": n_dlg, "menus": n_menu, "menu_items": len(items), "controls": len(ctrls),
                "buttons": buttons, "handlers": len(mapped)}


def _dialog_key(k: str) -> tuple[int, Any]:
    return (0, int(k)) if k.isdigit() else (1, k.lower())


def _uniq(items) -> list[str]:
    out: list[str] = []
    for x in items:
        if x not in out:
            out.append(x)
    return out


def _prefer(refs: list[CtrlRef], dialogs: list[str], strict: bool = False) -> list[CtrlRef]:
    """Controls of the class's own dialog when it has one and the id occurs there. ``strict`` also
    drops shared ids (IDOK..IDHELP) of a class that has no dialog of its own: they say nothing."""
    if dialogs:
        own = [r for r in refs if r.dialog in dialogs]
        if own:
            return own
    if strict:
        return [r for r in refs if r.ctrl_id not in GENERIC_IDS]
    return refs


def function_hints(store: Store, binary_id: int, entry: int) -> list[str]:
    """Hints for ``function``: the UI element a message map handler serves (empty when it is none)."""
    try:
        if not store.db.execute("SELECT 1 FROM msgmap_entry WHERE binary_id=? AND handler=? AND message IN (?,?) "
                                "LIMIT 1", (binary_id, entry, WM_COMMAND, WM_NOTIFY)).fetchone():
            return []
        return UiIndex(store, binary_id).handler_hints(entry)
    except Exception:  # noqa: BLE001  an extra: never break the function view
        return []


def ui_line(store: Store, binary_id: int) -> str:
    """One line for the project map: ``UI: 9 dialogs, 2 menus, 14 menu items and 3 buttons with a handler``;
    empty when the binary has no dialogs and no menus."""
    try:
        s = UiIndex(store, binary_id).summary()
    except Exception:  # noqa: BLE001
        return ""
    if not s["dialogs"] and not s["menus"]:
        return ""
    return (f"UI: {s['dialogs']} dialogs, {s['menus']} menus; handlers mapped: {s['menu_items']} menu items, "
            f"{s['controls']} controls ({s['buttons']} buttons), {s['handlers']} functions")
