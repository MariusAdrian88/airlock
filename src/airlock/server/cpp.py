"""MSVC RTTI, vtables and MFC message maps, parsed from the PE bytes (DESIGN 11).

No worker and no Ghidra: ``Image`` maps the sections of the stored artifact, the parsers walk the
structures, and ``derive_binary`` writes the derived rows (``rtti_class``, ``vtable_slot``,
``msgmap_entry``, schema v10). Pointer size and image base come from the PE header.

Layouts (all little endian):

* type descriptor: ``pVFTable`` (ptr), ``spare`` (ptr), ``name`` (``.?AVFoo@Bar@@``).
* complete object locator (COL): ``signature`` u32 (0 in 32-bit with absolute pointers, 1 in
  64-bit with image-relative ones), ``offset`` u32, ``cdOffset`` u32, ``pTypeDescriptor``,
  ``pClassDescriptor`` (+ ``pSelf`` in 64-bit); 4 bytes each. The vtable pointer array starts one
  pointer after the slot that holds the COL address.
* class hierarchy descriptor: ``signature``, ``attributes``, ``numBaseClasses``, ``pBaseClassArray``.
  Base class descriptor: ``pTypeDescriptor``, ``numContainedBases``, PMD (3 x i32), ``attributes``.
* ``AFX_MSGMAP``: ``{pfnGetBaseMap | pBaseMap, lpEntries}`` (two pointers);
  ``AFX_MSGMAP_ENTRY``: ``{UINT nMessage, nCode, nID, nLastID; UINT_PTR nSig; AFX_PMSG pfn}``,
  24 bytes in 32-bit and 32 bytes in 64-bit; the table ends with an all-zero entry.
"""

from __future__ import annotations

import bisect
import ctypes
import logging
import re
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import pefile

from airlock.index.store import Binary, Store

log = logging.getLogger("airlock")

CPP_VERSION = 2                   # 2: names for classes without RTTI, dispatch / interface / event maps
CPP_META = "cpp_version"          # meta key prefix; the full key is ``cpp_version:<binary id>``

MAX_SLOTS = 1024                  # slots read per vtable
MAX_MAP_ENTRIES = 8192
SIG_LIMIT = 0x100                 # AfxSig_* values stay far below this


def meta_key(binary_id: int) -> str:
    return f"{CPP_META}:{binary_id}"


# ── image ──────────────────────────────────────────────────────────────────

@dataclass
class Section:
    va: int                       # absolute address of the first byte
    data: bytes
    executable: bool
    vsize: int = 0

    @property
    def end(self) -> int:
        return self.va + max(len(self.data), self.vsize)


class Image:
    """Mapped view of a PE: sections keyed by absolute address, pointer size, image base."""

    def __init__(self, psize: int, base: int, sections: Iterable[Section]) -> None:
        self.psize = psize
        self.base = base
        self.sections = sorted(sections, key=lambda s: s.va)
        self._starts = [s.va for s in self.sections]
        self._code = [(s.va, s.end) for s in self.sections if s.executable]
        self._code_starts = [a for a, _ in self._code]

    @classmethod
    def from_pe(cls, path: str | Path) -> Image | None:
        try:
            pe = pefile.PE(str(path), fast_load=True)
        except (pefile.PEFormatError, OSError):
            return None
        try:
            if pe.OPTIONAL_HEADER.Magic == 0x20B:
                psize = 8
            elif pe.OPTIONAL_HEADER.Magic == 0x10B:
                psize = 4
            else:
                return None
            base = int(pe.OPTIONAL_HEADER.ImageBase)
            secs: list[Section] = []
            for s in pe.sections:
                va = base + int(s.VirtualAddress)
                vsize = int(s.Misc_VirtualSize) or int(s.SizeOfRawData)
                raw = s.get_data()[:max(vsize, 0)] if s.SizeOfRawData else b""
                ex = bool(s.Characteristics & 0x20000000) or bool(s.Characteristics & 0x20)
                secs.append(Section(va, bytes(raw), ex, vsize))
            return cls(psize, base, secs)
        finally:
            pe.close()

    # -- lookups --

    def section_at(self, va: int) -> Section | None:
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        s = self.sections[i]
        return s if va < s.end else None

    def in_image(self, va: int) -> bool:
        return self.section_at(va) is not None

    def is_code(self, va: int) -> bool:
        i = bisect.bisect_right(self._code_starts, va) - 1
        return i >= 0 and va < self._code[i][1]

    def is_data(self, va: int) -> bool:
        s = self.section_at(va)
        return s is not None and not s.executable

    def read(self, va: int, n: int) -> bytes | None:
        s = self.section_at(va)
        if s is None:
            return None
        off = va - s.va
        b = s.data[off:off + n]
        if len(b) < n:
            if off + n > s.end - s.va:
                return None
            b = b + b"\0" * (n - len(b))        # virtual tail of the section
        return b

    def u32(self, va: int) -> int | None:
        b = self.read(va, 4)
        return struct.unpack("<I", b)[0] if b is not None else None

    def i32(self, va: int) -> int | None:
        b = self.read(va, 4)
        return struct.unpack("<i", b)[0] if b is not None else None

    def ptr(self, va: int) -> int | None:
        b = self.read(va, self.psize)
        if b is None:
            return None
        return struct.unpack("<I" if self.psize == 4 else "<Q", b)[0]

    def ref(self, va: int) -> int | None:
        """A 4-byte reference field: absolute in 32-bit, image-relative in 64-bit."""
        v = self.u32(va)
        if v is None:
            return None
        return v if self.psize == 4 else self.base + v

    def cstr(self, va: int, limit: int = 512) -> str | None:
        s = self.section_at(va)
        if s is None:
            return None
        off = va - s.va
        end = s.data.find(b"\0", off, off + limit)
        if end < 0:
            return None
        return s.data[off:end].decode("latin-1")

    def data_words(self, size: int) -> Iterable[tuple[int, memoryview]]:
        """(section va, aligned view of ``size``-byte words) of the non-executable sections."""
        code = {4: "I", 8: "Q"}[size]
        for s in self.sections:
            if s.executable or not s.data:
                continue
            n = len(s.data) // size * size
            if n:
                yield s.va, memoryview(s.data)[:n].cast(code)


# ── names ──────────────────────────────────────────────────────────────────

_dbghelp: ctypes.WinDLL | None = None  # type: ignore[name-defined]
_dbghelp_lock = threading.Lock()


def _undname(mangled: str) -> str | None:
    """Template type names through dbghelp (Windows only); None when unavailable."""
    global _dbghelp
    try:
        with _dbghelp_lock:
            if _dbghelp is None:
                _dbghelp = ctypes.WinDLL("dbghelp.dll")      # type: ignore[attr-defined]
            buf = ctypes.create_string_buffer(2048)
            sym = ("??_R0" + mangled[1:] + "@8").encode("latin-1")
            if not _dbghelp.UnDecorateSymbolName(sym, buf, 2048, 0):
                return None
            return buf.value.decode("latin-1")
    except (OSError, AttributeError):
        return None


_KEYWORD = re.compile(r"\b(?:class|struct|union|enum) ")


def demangle(name: str) -> str:
    """``.?AVFoo@Bar@@`` -> ``Bar::Foo``. Templates go through dbghelp, with a plain fallback."""
    if not name.startswith(".?A") or len(name) < 5:
        return name
    body = name[4:]
    if "?$" in body:
        got = _undname(name)
        if got:
            got = got.replace(" `RTTI Type Descriptor'", "")
            got = _KEYWORD.sub("", got)
            return got.strip()
    if body.endswith("@@"):
        body = body[:-2]
    parts = [p for p in body.split("@") if p]
    out = []
    for p in reversed(parts):
        out.append("`anonymous namespace'" if p.startswith("?A0x") else p)
    return "::".join(out) or name


# ── RTTI ───────────────────────────────────────────────────────────────────

@dataclass
class RttiClass:
    name: str
    td: int
    col: int
    vtable: int | None
    offset: int = 0                              # COL offset (vtable position inside the object)
    bases: list[str] = field(default_factory=list)   # direct bases, in CHD order


_TD_NAME = re.compile(rb"\.\?A[VU][^\0]{1,400}\0")


def find_type_descriptors(img: Image) -> dict[int, str]:
    """Type descriptor address -> mangled name, for class and struct descriptors."""
    out: dict[int, str] = {}
    ps = img.psize
    for s in img.sections:
        if s.executable or not s.data:
            continue
        for m in _TD_NAME.finditer(s.data):
            va = s.va + m.start() - 2 * ps
            if va < s.va:
                continue
            vf = img.ptr(va)
            spare = img.ptr(va + ps)
            if vf is None or spare != 0:
                continue
            nm = m.group(0)[:-1].decode("latin-1")
            if "@@" not in nm:
                continue
            out[va] = nm
    return out


def _find_cols(img: Image, tds: dict[int, str]) -> list[tuple[int, int]]:
    """(col address, type descriptor address) for every valid COL."""
    ps = img.psize
    cols: list[tuple[int, int]] = []
    if ps == 4:
        keys = set(tds)
        want_sig = 0
    else:
        keys = {a - img.base for a in tds}
        want_sig = 1
    for va, words in img.data_words(4):
        for i, v in enumerate(words):
            if v not in keys or i < 3:
                continue
            if words[i - 3] != want_sig:
                continue
            col = va + 4 * (i - 3)
            if ps == 8 and (i + 2 >= len(words) or words[i + 2] != col - img.base):
                continue
            cd = img.ref(col + 16)
            if cd is None or not img.is_data(cd):
                continue
            td = v if ps == 4 else img.base + v
            cols.append((col, td))
    return cols


def _find_vtables(img: Image, cols: Iterable[int]) -> dict[int, list[int]]:
    """COL address -> vtable addresses (the array starts one pointer after the COL slot)."""
    want = set(cols)
    out: dict[int, list[int]] = {}
    ps = img.psize
    for va, words in img.data_words(ps):
        for i, v in enumerate(words):
            if v in want:
                out.setdefault(v, []).append(va + ps * (i + 1))
    return out


def vtable_slots(img: Image, vtable: int, limit: int = MAX_SLOTS) -> list[int]:
    """Function pointers from ``vtable`` on, until a slot that is not a code address."""
    out: list[int] = []
    ps = img.psize
    a = vtable
    while len(out) < limit:
        v = img.ptr(a)
        if v is None or not img.is_code(v):
            break
        out.append(v)
        a += ps
    return out


def _bases(img: Image, col: int, tds: dict[int, str]) -> list[str]:
    chd = img.ref(col + 16)
    if chd is None:
        return []
    n = img.u32(chd + 8)
    arr = img.ref(chd + 12)
    if not n or n > 256 or arr is None:
        return []
    entries: list[tuple[str | None, int]] = []
    for k in range(n):
        bcd = img.ref(arr + 4 * k)
        if bcd is None:
            return []
        td = img.ref(bcd)
        contained = img.u32(bcd + 4) or 0
        nm = tds.get(td) if td is not None else None
        if nm is None and td is not None:
            raw = img.cstr(td + 2 * img.psize)
            nm = raw if raw and raw.startswith(".?A") else None
        entries.append((nm, contained))
    out: list[str] = []
    i = 1                                  # entry 0 is the class itself
    while i < len(entries):
        nm, contained = entries[i]
        if nm:
            out.append(demangle(nm))
        i += 1 + contained
    return out


def parse_rtti(img: Image) -> list[RttiClass]:
    """All classes with RTTI, one per (type descriptor, COL); lowest vtable address wins."""
    tds = find_type_descriptors(img)
    if not tds:
        return []
    cols = _find_cols(img, tds)
    vts = _find_vtables(img, (c for c, _ in cols))
    out: list[RttiClass] = []
    seen: set[tuple[int, int]] = set()
    for col, td in sorted(cols):
        if (td, col) in seen:
            continue
        seen.add((td, col))
        vt = min(vts[col]) if col in vts else None
        out.append(RttiClass(demangle(tds[td]), td, col, vt, img.u32(col + 4) or 0,
                             _bases(img, col, tds)))
    return out


# ── MFC message maps ───────────────────────────────────────────────────────

# 32-bit getter: optional frame set-up/spill, ``mov eax, imm32``, optional frame tear-down, ``ret``.
# Built from hex so that the bytes stay readable: 55 8B EC = push ebp; mov ebp,esp; 51 = push ecx;
# 83 EC nn = sub esp,nn; 89 4D FC = mov [ebp-4],ecx; B8 = mov eax,imm32; 8B E5 5D = mov esp,ebp; pop ebp;
# C9 = leave; C3 = ret.
_GETTER32 = re.compile(
    b"(?:" + re.escape(bytes.fromhex("558bec")) + b")?"
    b"(?:" + re.escape(bytes.fromhex("51")) + b"|" + re.escape(bytes.fromhex("83ec")) + b".)?"
    b"(?:" + re.escape(bytes.fromhex("894dfc")) + b")?"
    b"[" + re.escape(bytes.fromhex("535657")) + b"]*"
    + re.escape(bytes.fromhex("b8")) + b"(....)"
    b"[" + re.escape(bytes.fromhex("5b5e5f")) + b"]*"
    b"(?:" + re.escape(bytes.fromhex("8be55d")) + b"|" + re.escape(bytes.fromhex("5d")) + b"|"
    + re.escape(bytes.fromhex("c9")) + b"|" + re.escape(bytes.fromhex("59")) + b")?"
    + re.escape(bytes.fromhex("c3")), re.S)
_LEA_RAX_RIP = bytes.fromhex("488d05")
_SUB_RSP_28 = bytes.fromhex("4883ec28")
_ADD_RSP_RET = bytes.fromhex("4883c428c3")


def returned_address(img: Image, fn: int, depth: int = 4) -> int | None:
    """The constant a trivial getter returns: ``mov eax, imm32; ret`` (32-bit, also with a frame),
    ``lea rax, [rip+d]; ret`` (64-bit), through ``jmp``/``call`` stubs."""
    b = img.read(fn, 24)
    if b is None or depth < 0:
        return None
    mask = 2 ** (8 * img.psize) - 1
    if img.psize == 4:
        m = _GETTER32.match(b)
        if m:
            return struct.unpack("<I", m.group(1))[0]
    else:
        if b[:3] == _LEA_RAX_RIP and b[7] == 0xC3:
            return (fn + 7 + struct.unpack_from("<i", b, 3)[0]) & mask
        if b[:4] == _SUB_RSP_28 and b[4] == 0xE8 and b[9:14] == _ADD_RSP_RET:
            return returned_address(img, (fn + 9 + struct.unpack_from("<i", b, 5)[0]) & mask, depth - 1)
    if b[0] == 0xE9:
        return returned_address(img, (fn + 5 + struct.unpack_from("<i", b, 1)[0]) & mask, depth - 1)
    if b[0] == 0xE8 and b[5] == 0xC3:
        return returned_address(img, (fn + 5 + struct.unpack_from("<i", b, 1)[0]) & mask, depth - 1)
    return None


@dataclass(frozen=True)
class MsgEntry:
    message: int
    code: int
    id: int
    last_id: int
    sig: int
    handler: int


def entry_size(psize: int) -> int:
    return 24 if psize == 4 else 32


def parse_msgmap(img: Image, addr: int) -> list[MsgEntry] | None:
    """Entries of the ``AFX_MSGMAP`` at ``addr``; None when it is not a plausible message map."""
    ps = img.psize
    if not img.is_data(addr):
        return None
    base, ents = img.ptr(addr), img.ptr(addr + ps)
    if base is None or ents is None or not img.is_data(ents):
        return None
    if base and not (img.is_data(base) or img.is_code(base)):
        return None
    es = entry_size(ps)
    fmt = "<6I" if ps == 4 else "<4IQQ"
    out: list[MsgEntry] = []
    for k in range(MAX_MAP_ENTRIES):
        raw = img.read(ents + k * es, es)
        if raw is None:
            return None
        m, code, nid, last, sig, pfn = struct.unpack(fmt, raw)
        if not (m or code or nid or last or sig or pfn):
            return out
        if m > 0xFFFF or not img.is_code(pfn):
            return None
        if m != 0xC000 and sig >= SIG_LIMIT:
            return None
        out.append(MsgEntry(m, code, nid, last, sig, pfn))
    return None


@dataclass
class MsgMap:
    cls: str
    map_addr: int
    entries: list[MsgEntry]


ANON_PREFIX = "anon_"           # a message map whose class has no RTTI: ``anon_<map address>``


def _ancestors(classes: list[RttiClass]) -> dict[str, set[str]]:
    direct: dict[str, set[str]] = {}
    for c in classes:
        direct.setdefault(c.name, set()).update(c.bases)
    out: dict[str, set[str]] = {}
    for name in direct:
        seen: set[str] = set()
        todo = list(direct[name])
        while todo:
            x = todo.pop()
            if x not in seen:
                seen.add(x)
                todo.extend(direct.get(x, ()))
        out[name] = seen
    return out


def find_msgmaps(img: Image, classes: list[RttiClass],
                 slots: dict[int, list[int]]) -> list[MsgMap]:
    """Message maps, from every function that is a trivial getter of a valid ``AFX_MSGMAP``.

    A function in a vtable of an RTTI class names the class; a class that only inherits the slot
    of its base is not an owner (the base, an ancestor of all others, is). Getters of classes
    without RTTI are found through any code pointer in the data sections and named
    ``anon_<map address>``."""
    ps = img.psize
    fn_map: dict[int, int | None] = {}
    maps: dict[int, list[MsgEntry] | None] = {}

    def map_of(fn: int) -> int | None:
        if fn not in fn_map:
            m = returned_address(img, fn)
            if m is not None:
                if m not in maps:
                    ents = parse_msgmap(img, m)
                    maps[m] = ents or None            # an empty map says nothing
                if maps[m] is None:
                    m = None
            fn_map[fn] = m
        return fn_map[fn]

    owners: dict[int, list[RttiClass]] = {}
    for c in classes:
        if c.vtable is None or c.offset != 0:
            continue
        for t in slots.get(c.vtable, ()):
            m = map_of(t)
            if m is not None and c not in owners.setdefault(m, []):
                owners[m].append(c)
    anc = _ancestors(classes)
    out: list[MsgMap] = []
    for m, cs in sorted(owners.items()):
        if len(cs) > 1:
            top = [c for c in cs if all(c.name == o.name or c.name in anc.get(o.name, ()) for o in cs)]
            cs = top or cs
        seen: set[str] = set()
        for c in cs:
            if c.name not in seen:
                seen.add(c.name)
                out.append(MsgMap(c.name, m, maps[m] or []))
    in_vtables = {t for c in classes if c.vtable is not None for t in slots.get(c.vtable, ())}
    cands: set[int] = set()
    for _va, words in img.data_words(ps):
        cands.update(v for v in set(words) if v not in in_vtables and img.is_code(v))
    for fn in sorted(cands):
        m = map_of(fn)
        if m is not None and m not in owners:
            owners[m] = []
            out.append(MsgMap(f"{ANON_PREFIX}{m:0{2 * ps}x}", m, maps[m] or []))
    return out


# ── message names ──────────────────────────────────────────────────────────

WM_NAMES = {
    0x01: "WM_CREATE", 0x02: "WM_DESTROY", 0x03: "WM_MOVE", 0x05: "WM_SIZE", 0x06: "WM_ACTIVATE",
    0x07: "WM_SETFOCUS", 0x08: "WM_KILLFOCUS", 0x0A: "WM_ENABLE", 0x0B: "WM_SETREDRAW",
    0x0C: "WM_SETTEXT", 0x0D: "WM_GETTEXT", 0x0E: "WM_GETTEXTLENGTH", 0x0F: "WM_PAINT",
    0x10: "WM_CLOSE", 0x11: "WM_QUERYENDSESSION", 0x12: "WM_QUIT", 0x13: "WM_QUERYOPEN",
    0x14: "WM_ERASEBKGND", 0x19: "WM_CTLCOLOR", 0x15: "WM_SYSCOLORCHANGE", 0x16: "WM_ENDSESSION", 0x18: "WM_SHOWWINDOW",
    0x1A: "WM_WININICHANGE", 0x1B: "WM_DEVMODECHANGE", 0x1C: "WM_ACTIVATEAPP", 0x1D: "WM_FONTCHANGE",
    0x1E: "WM_TIMECHANGE", 0x1F: "WM_CANCELMODE", 0x20: "WM_SETCURSOR", 0x21: "WM_MOUSEACTIVATE",
    0x22: "WM_CHILDACTIVATE", 0x24: "WM_GETMINMAXINFO", 0x26: "WM_PAINTICON", 0x2B: "WM_DRAWITEM",
    0x2C: "WM_MEASUREITEM", 0x2D: "WM_DELETEITEM", 0x2E: "WM_VKEYTOITEM", 0x2F: "WM_CHARTOITEM",
    0x30: "WM_SETFONT", 0x31: "WM_GETFONT", 0x32: "WM_SETHOTKEY", 0x37: "WM_QUERYDRAGICON",
    0x39: "WM_COMPAREITEM", 0x46: "WM_WINDOWPOSCHANGING", 0x47: "WM_WINDOWPOSCHANGED",
    0x4A: "WM_COPYDATA", 0x4E: "WM_NOTIFY", 0x50: "WM_INPUTLANGCHANGEREQUEST",
    0x51: "WM_INPUTLANGCHANGE", 0x53: "WM_HELP", 0x7B: "WM_CONTEXTMENU", 0x7D: "WM_STYLECHANGED",
    0x7E: "WM_DISPLAYCHANGE", 0x80: "WM_SETICON", 0x81: "WM_NCCREATE", 0x82: "WM_NCDESTROY",
    0x83: "WM_NCCALCSIZE", 0x84: "WM_NCHITTEST", 0x85: "WM_NCPAINT", 0x86: "WM_NCACTIVATE",
    0x87: "WM_GETDLGCODE", 0xA0: "WM_NCMOUSEMOVE", 0xA1: "WM_NCLBUTTONDOWN", 0xA2: "WM_NCLBUTTONUP",
    0xA3: "WM_NCLBUTTONDBLCLK", 0xA4: "WM_NCRBUTTONDOWN", 0xA5: "WM_NCRBUTTONUP",
    0x100: "WM_KEYDOWN", 0x101: "WM_KEYUP", 0x102: "WM_CHAR", 0x103: "WM_DEADCHAR",
    0x104: "WM_SYSKEYDOWN", 0x105: "WM_SYSKEYUP", 0x106: "WM_SYSCHAR", 0x110: "WM_INITDIALOG",
    0x111: "WM_COMMAND", 0x112: "WM_SYSCOMMAND", 0x113: "WM_TIMER", 0x114: "WM_HSCROLL",
    0x115: "WM_VSCROLL", 0x116: "WM_INITMENU", 0x117: "WM_INITMENUPOPUP", 0x11F: "WM_MENUSELECT",
    0x120: "WM_MENUCHAR", 0x121: "WM_ENTERIDLE", 0x125: "WM_UNINITMENUPOPUP", 0x127: "WM_CHANGEUISTATE",
    0x128: "WM_UPDATEUISTATE", 0x132: "WM_CTLCOLORMSGBOX", 0x133: "WM_CTLCOLOREDIT",
    0x134: "WM_CTLCOLORLISTBOX", 0x135: "WM_CTLCOLORBTN", 0x136: "WM_CTLCOLORDLG",
    0x137: "WM_CTLCOLORSCROLLBAR", 0x138: "WM_CTLCOLORSTATIC", 0x200: "WM_MOUSEMOVE",
    0x201: "WM_LBUTTONDOWN", 0x202: "WM_LBUTTONUP", 0x203: "WM_LBUTTONDBLCLK", 0x204: "WM_RBUTTONDOWN",
    0x205: "WM_RBUTTONUP", 0x206: "WM_RBUTTONDBLCLK", 0x207: "WM_MBUTTONDOWN", 0x208: "WM_MBUTTONUP",
    0x209: "WM_MBUTTONDBLCLK", 0x20A: "WM_MOUSEWHEEL", 0x210: "WM_PARENTNOTIFY", 0x211: "WM_ENTERMENULOOP",
    0x212: "WM_EXITMENULOOP", 0x214: "WM_SIZING", 0x215: "WM_CAPTURECHANGED", 0x216: "WM_MOVING",
    0x219: "WM_DEVICECHANGE", 0x231: "WM_ENTERSIZEMOVE", 0x232: "WM_EXITSIZEMOVE",
    0x233: "WM_DROPFILES", 0x2A1: "WM_MOUSEHOVER", 0x2A3: "WM_MOUSELEAVE", 0x301: "WM_COPY",
    0x302: "WM_PASTE", 0x303: "WM_CLEAR", 0x304: "WM_UNDO", 0x300: "WM_CUT",
    0x30F: "WM_PALETTECHANGED", 0x310: "WM_PALETTEISCHANGING", 0x311: "WM_QUERYNEWPALETTE",
    0x312: "WM_HOTKEY", 0x317: "WM_PRINT", 0x318: "WM_PRINTCLIENT", 0x31A: "WM_THEMECHANGED",
}
# MFC private messages worth a name (afxpriv.h)
WM_NAMES.update({0x036A: "WM_QUERYAFXWNDPROC", 0x0370: "WM_SIZEPARENT", 0x0371: "WM_SETMESSAGESTRING",
                 0x0372: "WM_IDLEUPDATECMDUI", 0x0373: "WM_INITIALUPDATE", 0x0374: "WM_COMMANDHELP",
                 0x0375: "WM_HELPHITTEST", 0x0376: "WM_EXITHELPMODE", 0x0377: "WM_RECALCPARENT",
                 0x0378: "WM_SIZECHILD", 0x0379: "WM_KICKIDLE", 0x037A: "WM_QUERYCENTERWND",
                 0x037B: "WM_DISABLEMODAL", 0x037C: "WM_FLOATSTATUS", 0x037D: "WM_ACTIVATETOPLEVEL"})

CN_NAMES = {0xFFFFFFFF: "UPDATE_COMMAND_UI", 0xFFFFFFFE: "EVENT", 0xFFFFFFFD: "OLECOMMAND",
            0xFFFFFFFC: "OLE_UNREGISTER"}
# WM_NOTIFY codes (NM_*)
NM_NAMES = {0xFFFFFFFF: "NM_OUTOFMEMORY", 0xFFFFFFFE: "NM_CLICK", 0xFFFFFFFD: "NM_DBLCLK",
            0xFFFFFFFC: "NM_RETURN", 0xFFFFFFFB: "NM_RCLICK", 0xFFFFFFFA: "NM_RDBLCLK",
            0xFFFFFFF9: "NM_SETFOCUS", 0xFFFFFFF8: "NM_KILLFOCUS", 0xFFFFFFF4: "NM_CUSTOMDRAW",
            0xFFFFFFF3: "NM_HOVER"}


def message_name(message: int) -> str:
    if message in WM_NAMES:
        return WM_NAMES[message]
    if message == 0xC000:
        return "WM_REGISTERED"
    if 0x400 <= message < 0x8000:
        return f"WM_USER+{message - 0x400}"
    if 0x8000 <= message < 0xC000:
        return f"WM_APP+{message - 0x8000}"
    return f"0x{message:04x}"


def entry_label(message: int, code: int) -> str:
    """``WM_COMMAND``, ``UPDATE_COMMAND_UI``, ``WM_COMMAND code 0x300``, ``WM_NOTIFY NM_CLICK``."""
    name = message_name(message)
    if message == 0x111:
        if code == 0:
            return "WM_COMMAND"
        if code in CN_NAMES:
            return CN_NAMES[code]
        return f"WM_COMMAND code 0x{code:x}"
    if message == 0x4E:
        return f"WM_NOTIFY {NM_NAMES.get(code, f'code 0x{code:x}')}" if code else "WM_NOTIFY"
    return name


# ── derivation ─────────────────────────────────────────────────────────────

SCHEMA_TABLES = ("rtti_class", "vtable_slot", "msgmap_entry", "mfc_class", "mfc_map_entry")


def clear_binary(store: Store, binary_id: int) -> None:
    for t in SCHEMA_TABLES:
        store.db.execute(f"DELETE FROM {t} WHERE binary_id=?", (binary_id,))


def parse_image(img: Image) -> tuple[list[RttiClass], dict[int, list[int]], list[MsgMap]]:
    classes = parse_rtti(img)
    slots: dict[int, list[int]] = {}
    for c in classes:
        if c.vtable is not None and c.vtable not in slots:
            slots[c.vtable] = vtable_slots(img, c.vtable)
    maps = find_msgmaps(img, classes, slots)
    return classes, slots, maps


def store_rows(store: Store, binary_id: int, classes: list[RttiClass],
               slots: dict[int, list[int]], maps: list[MsgMap], extra: Any = None) -> None:
    """``extra`` is a ``mfc.Mfc`` (classes without RTTI, dispatch / interface / event maps) or None."""
    with store.db:
        clear_binary(store, binary_id)
        store.db.executemany(
            "INSERT OR REPLACE INTO rtti_class(binary_id, name, td_addr, col_addr, vtable_addr, bases) "
            "VALUES (?,?,?,?,?,?)",
            [(binary_id, c.name, c.td, c.col, c.vtable, ", ".join(c.bases)) for c in classes])
        store.db.executemany(
            "INSERT INTO vtable_slot(binary_id, vtable_addr, slot, target) VALUES (?,?,?,?)",
            [(binary_id, vt, i, t) for vt, ts in slots.items() for i, t in enumerate(ts)])
        store.db.executemany(
            "INSERT INTO msgmap_entry(binary_id, class, map_addr, message, code, ctrl_id, last_id, "
            "sig, handler, seq) VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(binary_id, m.cls, m.map_addr, e.message, e.code, e.id, e.last_id, e.sig, e.handler, k)
             for m in maps for k, e in enumerate(m.entries)])
        if extra is not None:
            store.db.executemany(
                "INSERT OR REPLACE INTO mfc_class(binary_id, name, vtable_addr, rc_addr, obj_size, schema, base, "
                "map_addr, dialog, source) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(binary_id, c.name, c.vtable, c.rc, c.size, c.schema, c.base, c.map_addr, c.dialog, c.source)
                 for c in extra.classes])
            store.db.executemany(
                "INSERT INTO mfc_map_entry(binary_id, class, kind, map_addr, seq, name, id, vt, flags, pfn, "
                "pfn_set, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(binary_id, m.cls, m.kind, m.addr, e.seq, e.name, e.id, e.vt, e.flags, e.pfn or None,
                  e.pfn_set or None, e.extra) for m in extra.maps for e in m.entries])
        store.set_meta(meta_key(binary_id), str(CPP_VERSION))


def derive_binary(store: Store, binary_id: int, artifact: Path) -> tuple[int, int, int]:
    """Parse ``artifact`` and replace the C++ rows of the binary. Returns (classes, vtables,
    message map entries). A file that is not a PE stores nothing but is marked done."""
    img = Image.from_pe(artifact)
    if img is None:
        store_rows(store, binary_id, [], {}, [])
        return 0, 0, 0
    classes, slots, maps = parse_image(img)
    from airlock.server import mfc                                  # lazy: mfc imports this module
    extra = mfc.analyse(img, classes, slots, maps, artifact)         # renames anonymous maps in place
    store_rows(store, binary_id, classes, slots, maps, extra)
    return len(classes), len(slots), sum(len(m.entries) for m in maps)


def stale(store: Store, binary_id: int) -> bool:
    return store.get_meta(meta_key(binary_id)) != str(CPP_VERSION)


def ensure(store: Store, binary: Binary, artifact: Path) -> bool:
    """Derive the C++ rows of ``binary`` when missing or from an older CPP_VERSION. Never raises;
    returns True when rows were (re)written."""
    if not stale(store, binary.id) or not artifact.is_file():
        return False
    try:
        derive_binary(store, binary.id, artifact)
        return True
    except Exception as e:  # noqa: BLE001  an extra; the binary stays usable
        log.warning("C++ analysis of %s failed: %s", binary.name, e)
        return False


def ensure_project(store: Store, artifacts: Path) -> int:
    """``ensure`` for every ready binary (old projects get the tables on open, no re-analysis)."""
    n = 0
    for b in store.list_binaries():
        if store.get_meta(f"status:{b.id}") == "ready" and ensure(store, b, artifacts / b.sha256):
            n += 1
    return n


# ── name hints ─────────────────────────────────────────────────────────────

def hints_for(store: Store, binary_id: int, entry: int) -> list[str]:
    """Name hints for a function entry: ``Class::vslot N`` (vtable target, one entry per slot index,
    the other classes counted) and ``handler WM_COMMAND id N of Class`` (message map handler)."""
    out: list[str] = []
    q = store.db.execute
    by_slot: dict[int, list[str]] = {}
    for r in q("SELECT c.name, s.slot FROM vtable_slot s JOIN rtti_class c "
               "ON c.binary_id=s.binary_id AND c.vtable_addr=s.vtable_addr "
               "WHERE s.binary_id=? AND s.target=? ORDER BY s.slot, s.vtable_addr", (binary_id, entry)):
        names = by_slot.setdefault(r[1], [])
        if r[0] not in names:
            names.append(r[0])
    for slot, names in list(by_slot.items())[:3]:
        extra = f" (+{len(names) - 1} classes)" if len(names) > 1 else ""
        out.append(f"{names[0]}::vslot {slot}{extra}")
    rows = q("SELECT class, message, code, ctrl_id, last_id FROM msgmap_entry "
             "WHERE binary_id=? AND handler=? ORDER BY map_addr, seq LIMIT 4", (binary_id, entry)).fetchall()
    for r in rows:
        rng = f"-{r[4]}" if r[4] and r[4] != r[3] else ""
        ident = f" id {r[3]}{rng}" if r[3] or r[4] else ""
        out.append(f"handler {entry_label(r[1], r[2])}{ident} of {r[0]}")
    return out
