"""Route tables of MFC look-alike frameworks (DESIGN 11 "Route tables").

Some programs replace MFC with an own framework that keeps the MFC names (``CWnd``, ``CFrameWnd``,
``CCmdUI``) and the dispatch idea but stores the entries in ``constexpr`` arrays that a lazily
initialised static ``RouteTable {base, span<entries>}`` points to. The table in ``.data`` is zero in
the file; only the initialiser code names the entries and their count, so the getter based
``AFX_MSGMAP`` decoder finds nothing. Layouts (little endian, ``P`` = pointer size):

* entry: ``{u32 message, u32 code, u32 firstId, u32 lastId, P invoke, P registeredMessage}``,
  24 bytes in 32-bit, 32 in 64-bit. ``invoke`` is a template thunk that calls the member function;
  ``registeredMessage`` points to the id of a registered message (then ``message`` is 0).
* initialiser (64-bit): ``mov qword [rip+T+P+8], count`` ... ``lea r, [rip+entries]``,
  ``mov [rip+T+P], r``; the base table goes to ``[rip+T]`` (``lea rax, [rip+B]`` or a call).
  32-bit: ``mov dword [T+4], entries`` and ``mov dword [T+8], count`` **[verify]**.
* ``GetRouteTable`` (a vtable slot) returns ``&T``: ``lea rax, [rip+T]`` / ``mov eax, T`` and ``ret``.

Maps are named ``anon_<entries address>`` like other message maps without RTTI; handlers are the
member function the invoker calls (``this`` = the second argument in 64-bit), else the invoker.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from airlock.server.cpp import ANON_PREFIX, Image, MsgEntry, MsgMap

WM_COMMAND, WM_NOTIFY = 0x111, 0x4E
REGISTERED = 0xC000              # stored message of a registered-message entry (``WM_REGISTERED``)
MAX_ROUTES = 4096                # entries per table
WINDOW = 64                      # bytes around the entries store searched for the count / base store
GETTER_SCAN = 96                 # bytes of a function searched for ``return &T``

_RIP = b"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]"            # modrm of [rip+disp32], any register
# lea r64, [rip+E] ; mov [rip+P], r64   (same register)
_LEA_STORE64 = re.compile(b"([\x48\x4c])\x8d(" + _RIP + b")(....)([\x48\x4c])\x89(" + _RIP + b")(....)", re.S)
_STORE_IMM32 = re.compile(b"\xc7\x05(....)(....)", re.S)                  # mov dword [abs32], imm32
_LEA_RIP = re.compile(b"[\x48\x4c]\x8d" + _RIP + b"(....)", re.S)
_MOV_RR = re.compile(b"([\x48\x49\x4c\x4d])([\x8b\x8d])(.)", re.S)


@dataclass
class RouteTable:
    table: int                   # static RouteTable (zero in the file)
    entries: int                 # first entry
    rows: list[MsgEntry]
    base: int = 0                # RouteTable of the base class, 0 when unknown
    vtable: int = 0              # vtable whose GetRouteTable slot returns ``table``, 0 when not found


def entry_size(psize: int) -> int:
    return 16 + 2 * psize


def parse_routes(img: Image, addr: int, n: int) -> list[MsgEntry] | None:
    """The ``n`` route entries at ``addr``; None when one is not a valid entry."""
    ps = img.psize
    if not (0 < n <= MAX_ROUTES) or not img.is_data(addr):
        return None
    es = entry_size(ps)
    fmt = "<4III" if ps == 4 else "<4IQQ"
    out: list[MsgEntry] = []
    for k in range(n):
        raw = img.read(addr + k * es, es)
        if raw is None:
            return None
        m, code, lo, hi, inv, reg = struct.unpack(fmt, raw)
        if not img.is_code(inv) or lo > hi:
            return None
        if reg:
            if m or not img.is_data(reg):
                return None
            m = REGISTERED
        elif m == 0 or m > 0xFFFF:
            return None
        elif m not in (WM_COMMAND, WM_NOTIFY) and (code or lo or hi):
            return None                           # a window message entry carries no code or ids
        out.append(MsgEntry(m, code, lo, hi, 0, invoked(img, inv)))
    return out


def invoked(img: Image, inv: int) -> int:
    """The member function an invoker thunk calls: the first direct call whose ``rcx`` holds the
    incoming ``rdx`` (the target object), with only register moves tracked (64-bit). Else ``inv``."""
    if img.psize != 8:
        return inv
    b = img.read(inv, 64)
    if b is None:
        return inv
    held = {2}                                    # registers that hold the incoming rdx
    i = 0
    while i < len(b) - 4:
        op = b[i]
        if op == 0xC3 or op == 0xCC:
            return inv
        if op == 0xE8:
            t = (inv + i + 5 + struct.unpack_from("<i", b, i + 1)[0]) & 0xFFFFFFFFFFFFFFFF
            return t if 1 in held and img.is_code(t) and t != inv else inv
        m = _MOV_RR.match(b, i)
        if m:
            rex, opc, modrm = m.group(1)[0], m.group(2)[0], m.group(3)[0]
            dst = ((modrm >> 3) & 7) | (8 if rex & 4 else 0)
            if opc == 0x8B and modrm >= 0xC0:
                src = (modrm & 7) | (8 if rex & 1 else 0)
                (held.add if src in held else held.discard)(dst)
                i += 3
                continue
            held.discard(dst)                     # a load or lea overwrites the register
        i += 1
    return inv


def _rel(at: int, end: int, disp: bytes) -> int:
    return (end + struct.unpack("<i", disp)[0]) & 0xFFFFFFFFFFFFFFFF


def _count64(img: Image, va: int, data: bytes, pos: int, slot: int) -> int | None:
    """``mov qword|dword [rip+slot], imm32`` within WINDOW bytes of ``pos``."""
    lo, hi = max(0, pos - WINDOW), min(len(data), pos + WINDOW)
    for k in range(lo, hi):
        if data[k:k + 3] == b"\x48\xc7\x05" and k + 11 <= len(data):
            if _rel(va + k, va + k + 11, data[k + 3:k + 7]) == slot:
                return struct.unpack_from("<I", data, k + 7)[0]
        if data[k:k + 2] == b"\xc7\x05" and k + 10 <= len(data) and (k == 0 or data[k - 1] != 0x48):
            if _rel(va + k, va + k + 10, data[k + 2:k + 6]) == slot:
                return struct.unpack_from("<I", data, k + 6)[0]
    return None


def _base64(va: int, data: bytes, pos: int, table: int) -> tuple[int, int]:
    """The base table store ``mov [rip+table], rax`` within WINDOW bytes of ``pos``: (B, 0) after
    ``lea rax, [rip+B]``, (0, F) after ``call F`` (F returns the base table), else (0, 0)."""
    lo, hi = max(0, pos - WINDOW), min(len(data), pos + WINDOW)
    for k in range(lo, hi - 7):
        if data[k:k + 3] == b"\x48\x89\x05" and _rel(va + k, va + k + 7, data[k + 3:k + 7]) == table:
            for j in range(k - 5, max(lo, k - 40) - 1, -1):
                if data[j:j + 3] == b"\x48\x8d\x05" and j + 7 <= k:
                    return _rel(va + j, va + j + 7, data[j + 3:j + 7]), 0
                if data[j] == 0xE8 and j + 5 <= k:
                    return 0, _rel(va + j, va + j + 5, data[j + 1:j + 5])
            return 0, 0
    return 0, 0


def _code(img: Image):
    return [(s.va, s.data) for s in img.sections if s.executable and s.data]


def find_tables(img: Image) -> list[RouteTable]:
    """Route tables from their initialisers, one per entries address."""
    found: dict[int, RouteTable] = {}
    calls: dict[int, int] = {}                    # entries -> function that returns the base table
    ps = img.psize
    for va, data in _code(img):
        if ps == 8:
            for m in _LEA_STORE64.finditer(data):
                if m.group(1) != m.group(4) or (m.group(2)[0] & 0x38) != (m.group(5)[0] & 0x38):
                    continue
                at = va + m.start()
                ents = _rel(at, at + 7, m.group(3))
                slot = _rel(at + 7, at + 14, m.group(6))
                if ents in found or not img.is_data(ents) or not img.in_image(slot):
                    continue
                n = _count64(img, va, data, m.start(), slot + 8)
                rows = parse_routes(img, ents, n or 0)
                if rows:
                    tab = slot - 8
                    base, call = _base64(va, data, m.start(), tab)
                    found[ents] = RouteTable(tab, ents, rows, base)
                    if call:
                        calls[ents] = call
        else:
            stores = [(va + m.start(), struct.unpack("<I", m.group(1))[0], struct.unpack("<I", m.group(2))[0])
                      for m in _STORE_IMM32.finditer(data)]
            near: dict[int, list[tuple[int, int]]] = {}
            for at, dst, imm in stores:
                near.setdefault(dst, []).append((at, imm))
            for at, dst, ents in stores:
                if ents in found or not img.is_data(ents) or not img.in_image(dst):
                    continue
                n = next((imm for a2, imm in near.get(dst + 4, ()) if abs(a2 - at) <= WINDOW), 0)
                rows = parse_routes(img, ents, n)
                if rows:
                    tab = dst - 4
                    base = next((imm for a2, imm in near.get(tab, ()) if abs(a2 - at) <= WINDOW), 0)
                    found[ents] = RouteTable(tab, ents, rows, base)
    keys = {t.table for t in found.values()}
    for ents, fn in calls.items():
        found[ents].base = _returns(img, fn, keys) or 0
    tables = sorted(found.values(), key=lambda t: t.entries)
    _vtables(img, tables)
    return tables


def _returns(img: Image, fn: int, tabs: set[int], depth: int = 2) -> int | None:
    """The table a ``GetRouteTable`` function returns: ``lea rax, [rip+T]`` / ``mov eax, T`` followed
    by ``ret`` within 16 bytes, in the first GETTER_SCAN bytes; through a leading ``jmp``."""
    b = img.read(fn, GETTER_SCAN)
    if b is None:
        return None
    if b[0] == 0xE9 and depth > 0:
        return _returns(img, _rel(fn, fn + 5, b[1:5]) & (2 ** (8 * img.psize) - 1), tabs, depth - 1)
    pat = b"\x48\x8d\x05" if img.psize == 8 else b"\xb8"
    i = b.find(pat)
    while i >= 0:
        if img.psize == 8 and i + 7 <= len(b):
            t = _rel(fn + i, fn + i + 7, b[i + 3:i + 7])
            end = i + 7
        elif img.psize == 4 and i + 5 <= len(b):
            t, end = struct.unpack_from("<I", b, i + 1)[0], i + 5
        else:
            break
        if t in tabs and 0xC3 in b[end:end + 16]:
            return t
        i = b.find(pat, i + 1)
    return None


def _code_refs(img: Image) -> set[int]:
    """Data addresses code loads (``lea r, [rip+X]``; 32-bit ``mov [r], imm32`` / ``mov r, imm32``)."""
    out: set[int] = set()
    for va, data in _code(img):
        if img.psize == 8:
            for m in _LEA_RIP.finditer(data):
                out.add(_rel(va + m.start(), va + m.end(), m.group(1)))
        else:
            for m in re.finditer(b"(?:\xc7[\x00-\x07]|[\xb8-\xbf])(....)", data, re.S):
                out.add(struct.unpack("<I", m.group(1))[0])
    return out


def _vtables(img: Image, tables: list[RouteTable]) -> None:
    """Set ``vtable`` of each table: the vtable that holds its GetRouteTable slot. The vtable starts at
    the closest address before the slot that code loads, with only code pointers in between."""
    by_tab = {t.table: t for t in tables}
    if not by_tab:
        return
    ps = img.psize
    keys = set(by_tab)
    getters: dict[int, int | None] = {}
    slots: dict[int, int] = {}                    # table -> lowest slot address
    for va, words in img.data_words(ps):
        for k, w in enumerate(words):
            if not w or not img.is_code(w):
                continue
            if w not in getters:
                getters[w] = _returns(img, w, keys)
            t = getters[w]
            if t is not None:
                a = va + k * ps
                if t not in slots or a < slots[t]:
                    slots[t] = a
    if not slots:
        return
    refs = _code_refs(img)
    for t, slot in slots.items():
        a = slot
        while a >= slot - 512 * ps:
            if a in refs:
                by_tab[t].vtable = a
                break
            p = img.ptr(a - ps)
            if p is None or not img.is_code(p):
                break
            a -= ps


def find_route_maps(img: Image) -> list[MsgMap]:
    """Message maps of kind ``routes`` (``anon_<entries address>``, map address = first entry)."""
    tables = find_tables(img)
    ents = {t.table: t.entries for t in tables}
    return [MsgMap(name_of(img, t), t.entries, t.rows, "routes", t.vtable, ents.get(t.base, 0))
            for t in tables]


def name_of(img: Image, t: RouteTable) -> str:
    return f"{ANON_PREFIX}{t.entries:0{2 * img.psize}x}"
