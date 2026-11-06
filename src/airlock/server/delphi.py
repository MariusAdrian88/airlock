"""Delphi classes (VMT), published methods and DFM forms, parsed from the PE bytes (DESIGN 11).

No worker and no Ghidra: ``cpp.Image`` maps the sections of the stored artifact, the parsers walk the
structures and ``derive_binary`` writes the derived rows (``dl_*`` tables, schema v12).

VMT layout (Delphi 2009 and later; every slot is one pointer wide, so offsets scale with the pointer
size ``ps``). The class reference points at slot 22; the 22 slots before it hold, in order from the
lowest address: ``vmtSelfPtr`` (the class reference itself), ``vmtIntfTable``, ``vmtAutoTable``,
``vmtInitTable``, ``vmtTypeInfo``, ``vmtFieldTable``, ``vmtMethodTable``, ``vmtDynamicTable``,
``vmtClassName`` (ShortString), ``vmtInstanceSize``, ``vmtParent`` (pointer to a cell holding the
parent class reference), then ``Equals``, ``GetHashCode``, ``ToString``, ``SafeCallException``,
``AfterConstruction``, ``BeforeDestruction``, ``Dispatch``, ``DefaultHandler``, ``NewInstance``,
``FreeInstance``, ``Destroy``. Delphi 2007 and older have 19 slots (no ``Equals``, ``GetHashCode``,
``ToString``); the first 11 slots are the same. Virtual methods follow at the class reference.

* method table: ``u16 count`` then entries ``{u16 size; ptr code; ShortString name; ...}``, ``size``
  covers the whole entry (extended RTTI follows the name inside it).
* extended method table (Delphi 2010 and later): right after the ``count`` entries, ``u16 exCount`` and
  ``exCount`` records ``{ptr entry; u16 flags; i16 virtualIndex}`` (``ps + 4`` bytes, packed). ``entry``
  points to a method entry of the layout above (it need not lie in the table). It names every method that
  has RTTI, published or not. Flags: bits 0-2 kind (1 static class method, 2 method, 3 class method, 4
  constructor, 5 destructor), bits 3-4 dispatch (0 static, 1 virtual, 2 dynamic, 3 message), bits 5-6
  visibility (0 private, 1 protected, 2 public, 3 published), bit 7 abstract. ``virtualIndex`` is the vtable
  index for virtual methods (the message number for message methods), negative otherwise.
* field table: ``u16 count; ptr classTab`` then entries ``{uint offset (pointer wide); u16 typeIndex;
  ShortString name}``; ``classTab`` is ``u16 count`` and pointers to class reference cells.
* type info (``vmtTypeInfo``): ``u8 kind (7 = class); ShortString name``, then ``ptr classType; ptr
  parentInfo; i16 propCount; ShortString unitName``.

DFM (``RCDATA`` starting with ``TPF0``): see ``parse_dfm``.
"""

from __future__ import annotations

import logging
from bisect import bisect_right
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pefile

from airlock.index.store import Binary, Store
from airlock.projects import FPC_VERSION_RE
from airlock.server import peres
from airlock.server.cpp import Image

log = logging.getLogger("airlock")

DELPHI_VERSION = 6          # 4: Free Pascal classes; 5: FPC message / interface / init tables, virtual names; 6: FPC interface method names
DELPHI_META = "delphi_version"     # meta key prefix; the full key is ``delphi_version:<binary id>``

MAX_VIRTUAL = 1024                 # virtual method slots read per class
MAX_PUBLISHED = 4096
MAX_RTTI = 16384                   # extended method entries read per class
MAX_PROPS = 4096                   # properties read per class
MAX_COMPONENTS = 20000             # per form
MAX_DEPTH = 64
MIN_SLOTS, MAX_SLOTS = 19, 32      # slots before the class reference (22 in 32-bit Delphi 2009+, 19 older)

_IDENT = re.compile(r"^[A-Za-z_][\w.<>,$&+ \[\]]*$")


def meta_key(binary_id: int) -> str:
    return f"{DELPHI_META}:{binary_id}"


# ── classes ────────────────────────────────────────────────────────────────

@dataclass
class DlMethod:
    kind: str            # published | virtual | rtti-private | rtti-protected | rtti-public | rtti-published |
    #                      prop-get | prop-set (accessor method of a property; ``name`` is the property)
    slot: int            # virtual: vtable slot; rtti: virtual index (-1 when not virtual)
    name: str
    addr: int


@dataclass
class DlField:
    name: str
    offset: int
    type: str = ""


@dataclass
class DlClass:
    vmt: int
    name: str
    size: int
    unit: str = ""
    typeinfo: int = 0
    parent_vmt: int = 0
    parent: str = ""
    methods: list[DlMethod] = field(default_factory=list)
    fields: list[DlField] = field(default_factory=list)

    @property
    def nvirtual(self) -> int:
        return sum(1 for m in self.methods if m.kind == "virtual")


def _sstr(img: Image, va: int) -> str | None:
    """A ShortString (length byte, then characters) that looks like an identifier."""
    if not va:
        return None
    b = img.read(va, 1)
    if not b or b[0] == 0:
        return None
    raw = img.read(va + 1, b[0])
    if raw is None:
        return None
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if _IDENT.match(s) else None


def _sstr_raw(img: Image, va: int) -> tuple[str, int] | None:
    """(text, length byte) of a ShortString without the identifier check (bytes decoded as latin-1)."""
    b = img.read(va, 1)
    if b is None:
        return None
    raw = img.read(va + 1, b[0]) if b[0] else b""
    if raw is None:
        return None
    return raw.decode("latin-1"), b[0]


def _u16(img: Image, va: int) -> int | None:
    b = img.read(va, 2)
    return struct.unpack("<H", b)[0] if b is not None else None


def _scan(img: Image) -> dict[int, list[int]]:
    """{class reference: candidate slot counts, largest first}: aligned words that hold their own address plus a small
    distance (``MIN_SLOTS`` to ``MAX_SLOTS`` pointers), the vmtSelfPtr pattern."""
    ps = img.psize
    lo_d, hi_d = MIN_SLOTS * ps, MAX_SLOTS * ps
    code = "I" if ps == 4 else "Q"
    out: dict[int, list[int]] = {}
    for s in img.sections:
        n = len(s.data) // ps * ps
        if not n:
            continue
        mv = memoryview(s.data)[:n].cast(code)
        va = s.va
        # a word at index i sits at va + i*ps
        for i, w in enumerate(mv):
            d = w - va - i * ps
            if lo_d <= d <= hi_d and d % ps == 0:
                out.setdefault(w, []).append(d // ps)
    return {w: sorted(ds, reverse=True) for w, ds in out.items()}


def _read_class(img: Image, vmt: int, d_slots: int) -> DlClass | None:
    ps = img.psize
    lo = vmt - d_slots * ps

    def slot(k: int) -> int | None:
        return img.ptr(lo + k * ps)

    name_p = slot(8)
    name = _sstr(img, name_p) if name_p else None
    if name is None:
        return None
    sz = img.u32(lo + 9 * ps)
    if sz is None or sz < ps or sz > 0x1000000:
        return None
    ti = slot(4) or 0
    if ti and not img.in_image(ti):
        return None
    return DlClass(vmt=vmt, name=name, size=sz, typeinfo=ti)


def _unit_name(img: Image, ti: int, kind: int = 7) -> str:
    if not ti:
        return ""
    ps = img.psize
    k = img.read(ti, 1)
    if not k or k[0] != kind:
        return ""
    nm = _sstr_raw(img, ti + 1)
    if nm is None:
        return ""
    p = ti + 2 + nm[1] + 2 * ps + 2
    u = _sstr(img, p)
    return u or ""


def _published(img: Image, c: DlClass, tab: int) -> list[DlMethod]:
    ps = img.psize
    n = _u16(img, tab)
    if n is None or n > MAX_PUBLISHED:
        return []
    out: list[DlMethod] = []
    p = tab + 2
    for i in range(n):
        size = _u16(img, p)
        if size is None or size < 2 + ps + 2:
            break
        code = img.ptr(p + 2)
        name = _sstr(img, p + 2 + ps)
        if code is None or name is None or not img.is_code(code):
            break
        out.append(DlMethod("published", i, name, code))
        p += size
    return out


_VISIBILITY = ("private", "protected", "public", "published")


def _rtti_methods(img: Image, tab: int) -> list[DlMethod]:
    """Methods named by the extended method table that follows the published entries (Delphi 2010+; empty
    when the table is absent or does not parse: older compilers put other data there)."""
    ps = img.psize
    n = _u16(img, tab)
    if n is None or n > MAX_PUBLISHED:
        return []
    p = tab + 2
    for _ in range(n):
        size = _u16(img, p)
        if size is None or size < 2 + ps + 2:
            return []
        p += size
    ex = _u16(img, p)
    if not ex or ex > MAX_RTTI:
        return []
    out: list[DlMethod] = []
    q = p + 2
    for i in range(ex):
        raw = img.read(q, ps + 4)
        q += ps + 4
        if raw is None:
            break
        entry = int.from_bytes(raw[:ps], "little")
        flags, vindex = struct.unpack("<Hh", raw[ps:])
        code = img.ptr(entry + 2) if img.in_image(entry) else None
        name = _sstr(img, entry + 2 + ps) if code is not None else None
        if name is None:
            if i == 0:
                return []                  # not an extended table
            break
        if not code or not img.is_code(code):
            continue                       # abstract method: no code
        kind = "rtti-" + _VISIBILITY[(flags >> 5) & 3]
        out.append(DlMethod(kind, vindex if (flags >> 3) & 3 == 1 else -1, name, code))
    return out


PROP_FIELD, PROP_VIRTUAL = 0xFF, 0xFE
PROP_KINDS = ("prop-get", "prop-set")


def accessor_name(kind: str, prop: str) -> str:
    """Conventional method name of a property accessor: ``Get<Prop>`` / ``Set<Prop>``."""
    return ("Get" if kind == "prop-get" else "Set") + prop


def _prop_target(img: Image, vmt: int, w: int) -> tuple[int, int] | None:
    """(code address, vtable slot or -1) of an accessor word of a ``TPropInfo``. The top byte selects the
    encoding: ``0xFF`` the accessor is a field (offset in the low bits), ``0xFE`` a virtual method (the low
    16 bits are the byte offset of the slot from the class reference), anything else is the code address."""
    ps = img.psize
    top = w >> (8 * ps - 8)
    if top == PROP_FIELD:
        return None
    if top == PROP_VIRTUAL:
        off = w & 0xFFFF
        if off % ps or off >= MAX_VIRTUAL * ps:
            return None
        t = img.ptr(vmt + off)
        return (t, off // ps) if t and img.is_code(t) else None
    return (w, -1) if w and img.is_code(w) else None


def _prop_info(img: Image, at: int) -> tuple[str, int, int, int] | None:
    """(name, GetProc, SetProc, record size) of the packed ``TPropInfo`` at ``at``: ``PropType, GetProc,
    SetProc, StoredProc`` (pointers), ``Index`` (i32), ``Default`` (i32), ``NameIndex`` (i16), ShortString name."""
    ps = img.psize
    raw = img.read(at, 4 * ps + 10)
    if raw is None:
        return None
    nm = _sstr(img, at + 4 * ps + 10)
    if nm is None:
        return None
    return (nm, int.from_bytes(raw[ps:2 * ps], "little"), int.from_bytes(raw[2 * ps:3 * ps], "little"),
            4 * ps + 11 + len(nm))


def _properties(img: Image, c: DlClass) -> list[DlMethod]:
    """Accessor methods of the properties that the class declares (``DlMethod`` kinds ``prop-get`` and
    ``prop-set``, ``name`` = property). Sources: the property list that follows the unit name in the class
    type info (published properties) and the extended list after it (Delphi 2010+; records ``{u8 flags;
    ptr info; u16 attrLen; attributes}`` whose ``info`` points to a ``TPropInfo``, for any visibility)."""
    ps = img.psize
    ti = c.typeinfo
    k = img.read(ti, 1) if ti else None
    if not k or k[0] != 7:
        return []
    nm = _sstr_raw(img, ti + 1)
    if nm is None:
        return []
    p = ti + 2 + nm[1] + 2 * ps
    un = _sstr_raw(img, p + 2)
    if un is None:
        return []
    q = p + 3 + un[1]
    n = _u16(img, q)
    if n is None or n > MAX_PROPS:
        return []
    q += 2
    infos: list[int] = []
    for _ in range(n):
        got = _prop_info(img, q)
        if got is None:
            return []
        infos.append(q)
        q += got[3]
    ex = _u16(img, q)
    if ex and ex <= MAX_PROPS:
        q += 2
        for i in range(ex):
            raw = img.read(q, 1 + ps + 2)
            if raw is None:
                break
            info = int.from_bytes(raw[1:1 + ps], "little")
            alen = int.from_bytes(raw[1 + ps:], "little")
            if not img.in_image(info) or _prop_info(img, info) is None or alen < 2 or alen > 4096:
                if i == 0:
                    ex = 0
                break
            infos.append(info)
            q += 1 + ps + alen
    out: list[DlMethod] = []
    seen: set[tuple[str, int]] = set()
    for at in infos:
        got = _prop_info(img, at)
        if got is None:
            continue
        for kind, w in (("prop-get", got[1]), ("prop-set", got[2])):
            t = _prop_target(img, c.vmt, w)
            if t is not None and (kind, t[0]) not in seen:
                seen.add((kind, t[0]))
                out.append(DlMethod(kind, t[1], got[0], t[0]))
    return out


def _fields(img: Image, tab: int, by_vmt: dict[int, DlClass], first: int = 0) -> list[DlField]:
    """Published fields; ``first`` is the type index of the first class table entry (FPC counts from 1, 0 = none)."""
    ps = img.psize
    n = _u16(img, tab)
    if n is None or n > MAX_PUBLISHED or n == 0:
        return []
    ctab = img.ptr(tab + 2) or 0
    ncls = (_u16(img, ctab) or 0) if ctab else 0
    for osz in (ps, 4):                           # offset field width: pointer wide, else 4
        out: list[DlField] = []
        p = tab + 2 + ps
        ok = True
        for _ in range(n):
            ob = img.read(p, osz)
            ti = _u16(img, p + osz)
            name = _sstr(img, p + osz + 2)
            if ob is None or ti is None or name is None:
                ok = False
                break
            tname = ""
            if ctab and first <= ti < ncls + first:
                cell = img.ptr(ctab + 2 + (ti - first) * ps)
                tgt = img.ptr(cell) if cell else None
                k = by_vmt.get(tgt or 0) or by_vmt.get(cell or 0)
                tname = k.name if k else ""
            out.append(DlField(name, int.from_bytes(ob, "little"), tname))
            p += osz + 2 + 1 + len(name)
        if ok:
            return out
    return []


def _virtuals(img: Image, vmt: int, limit: int) -> list[DlMethod]:
    ps = img.psize
    out: list[DlMethod] = []
    for i in range(min(limit, MAX_VIRTUAL)):
        t = img.ptr(vmt + i * ps)
        if t is None or not img.is_code(t):
            break
        out.append(DlMethod("virtual", i, "", t))
    return out


def has_fpc_marker(img: Image) -> bool:
    """True when the image holds the version string that the Free Pascal RTL links into every program."""
    return any(FPC_VERSION_RE.search(s.data) for s in img.sections)


def parse_classes(img: Image, vslots: dict[str, dict[int, str]] | None = None,
                  guid_names: dict[str, str] | None = None) -> list[DlClass]:
    """All classes of a Pascal program, sorted by address: the Free Pascal parser when the image carries the
    FPC version string, else the Delphi parser; the other one is tried when the first finds nothing.
    ``vslots`` / ``guid_names``: names of Free Pascal virtual slots and interfaces (``parse_fpc_classes``)."""
    if has_fpc_marker(img):
        return parse_fpc_classes(img, vslots, guid_names) or _parse_delphi_classes(img)
    return _parse_delphi_classes(img) or parse_fpc_classes(img, vslots, guid_names)


def _parse_delphi_classes(img: Image) -> list[DlClass]:
    """All classes with a Delphi VMT, sorted by address; parents, units, published methods and fields
    filled in."""
    ps = img.psize
    found: dict[int, tuple[DlClass, int]] = {}
    for vmt, ds in _scan(img).items():
        for d in ds:                     # the self pointer is the lowest slot: try the longest distance first
            c = _read_class(img, vmt, d)
            if c is not None:
                found[vmt] = (c, d)
                break
    by_vmt = {v: c for v, (c, _d) in found.items()}
    order = sorted(found)
    for i, vmt in enumerate(order):
        c, d = found[vmt]
        lo = vmt - d * ps
        cell = img.ptr(lo + 10 * ps) or 0
        if cell:
            tgt = img.ptr(cell)
            pv = tgt if tgt in by_vmt else (cell if cell in by_vmt else 0)
            if pv and pv != vmt:
                c.parent_vmt = pv
                c.parent = by_vmt[pv].name
        c.unit = _unit_name(img, c.typeinfo)
        mt = img.ptr(lo + 6 * ps) or 0
        if mt:
            c.methods.extend(_published(img, c, mt))
            have = {(m.name, m.addr) for m in c.methods}
            c.methods.extend(m for m in _rtti_methods(img, mt) if (m.name, m.addr) not in have)
        ft = img.ptr(lo + 5 * ps) or 0
        if ft:
            c.fields = _fields(img, ft, by_vmt)
        named = {m.addr for m in c.methods}
        c.methods.extend(m for m in _properties(img, c) if m.addr not in named)
        nxt = order[i + 1] - found[order[i + 1]][1] * ps if i + 1 < len(order) else vmt + MAX_VIRTUAL * ps
        c.methods.extend(_virtuals(img, vmt, max(0, (nxt - vmt) // ps)))
    for c in by_vmt.values():             # a property whose accessor an ancestor already declares (a redeclared
        anc = ancestors(c, by_vmt)[1:]    # ``published`` property) belongs to the ancestor
        up_p = {(m.kind, m.addr) for a in anc for m in a.methods if m.kind in PROP_KINDS}
        if up_p:
            c.methods = [m for m in c.methods if m.kind not in PROP_KINDS or (m.kind, m.addr) not in up_p]
    for c in by_vmt.values():             # a method that a parent already names belongs to the parent
        if not any(m.kind.startswith("rtti") for m in c.methods):
            continue
        up = {(m.name, m.addr) for a in ancestors(c, by_vmt)[1:] for m in a.methods if m.kind != "virtual"}
        if up:
            c.methods = [m for m in c.methods if m.kind == "virtual" or (m.name, m.addr) not in up]
    return [found[v][0] for v in order]


# ── Free Pascal (FPC) classes ──────────────────────────────────────────────

FPC_TKCLASS = 15           # type kind of a class in FPC's TTypeKind (Delphi uses 7)
FPC_METHOD_START = 12      # pointer slots before the first virtual method (vmtMethodStart)
_FPC_MAX_INSTANCE = 0x1000000


def _fpc_scan(img: Image) -> list[int]:
    """Class references (= VMT start) of FPC classes: aligned words ``n`` followed by ``-n`` (``vmtInstanceSize``
    and ``vmtInstanceSize2``). Unlike a Delphi VMT the class reference points at the start of the table."""
    ps = img.psize
    mask = (1 << (8 * ps)) - 1
    code = "I" if ps == 4 else "Q"
    out: list[int] = []
    for s in img.sections:
        n = len(s.data) // ps * ps
        if n < 2 * ps:
            continue
        mv = memoryview(s.data)[:n].cast(code)
        va = s.va
        for i in range(len(mv) - 1):
            a = mv[i]
            if ps <= a <= _FPC_MAX_INSTANCE and mv[i + 1] == (-a) & mask:
                out.append(va + i * ps)
    return out


def _fpc_table_ok(img: Image, p: int | None) -> bool:
    return p is not None and (p == 0 or img.in_image(p))


def _fpc_read_class(img: Image, vmt: int) -> DlClass | None:
    """The class at ``vmt``: ``vmtInstanceSize, vmtInstanceSize2, vmtParent, vmtClassName, vmtDynamicTable,
    vmtMethodTable, vmtFieldTable, vmtTypeInfo, vmtInitTable, vmtAutoTable, vmtIntfTable, vmtMsgStrTable``
    (pointers; sizes are pointer wide), then the virtual methods."""
    ps = img.psize
    w = [img.ptr(vmt + k * ps) for k in range(FPC_METHOD_START)]
    if any(x is None for x in w) or not all(_fpc_table_ok(img, x) for x in w[2:]):
        return None
    name = _sstr(img, w[3]) if w[3] else None
    if name is None:
        return None
    ti = w[7]
    if ti:
        k = img.read(ti, 1)
        nm = _sstr_raw(img, ti + 1)
        if not k or k[0] != FPC_TKCLASS or nm is None or img.ptr(ti + 2 + nm[1]) != vmt:
            return None                      # type info of a class names its own class reference
    return DlClass(vmt=vmt, name=name, size=w[0], typeinfo=ti)


def _fpc_published(img: Image, tab: int) -> list[DlMethod]:
    """Method name table: ``u32 count`` then packed ``{ptr name (ShortString); ptr code}`` entries."""
    ps = img.psize
    raw = img.read(tab, 4)
    n = struct.unpack("<I", raw)[0] if raw else 0
    if n == 0 or n > MAX_PUBLISHED:
        return []
    out: list[DlMethod] = []
    p = tab + 4
    for i in range(n):
        name_p, code = img.ptr(p), img.ptr(p + ps)
        name = _sstr(img, name_p) if name_p else None
        if name is None or not code or not img.is_code(code):
            break
        out.append(DlMethod("published", i, name, code))
        p += 2 * ps
    return out


def _fpc_prop_info(img: Image, at: int) -> tuple[str, int, int, int, int] | None:
    """(name, GetProc, SetProc, PropProcs, record size) of the packed ``TPropInfo`` at ``at``: ``PropType,
    GetProc, SetProc, StoredProc`` (pointers), ``Index`` (i32), ``Default`` (i32), ``NameIndex`` (i16),
    ``PropProcs`` (u8), ShortString name."""
    ps = img.psize
    raw = img.read(at, 4 * ps + 11)
    if raw is None:
        return None
    nm = _sstr(img, at + 4 * ps + 11)
    if nm is None:
        return None
    return (nm, int.from_bytes(raw[ps:2 * ps], "little"), int.from_bytes(raw[2 * ps:3 * ps], "little"),
            raw[4 * ps + 10], 4 * ps + 12 + len(nm))


def _fpc_properties(img: Image, c: DlClass) -> list[DlMethod]:
    """Accessor methods of the published properties of the class (type info ``tkClass``: ``ClassType,
    ParentInfo`` pointers, ``i16 PropCount``, ShortString unit, ``u16 count``, then packed ``TPropInfo``
    records). ``PropProcs`` holds two bits per accessor: 0 field, 1 static method (``GetProc`` is the code
    address), 2 virtual method (``GetProc`` is the byte offset in the VMT), 3 constant."""
    ps = img.psize
    ti = c.typeinfo
    k = img.read(ti, 1) if ti else None
    if not k or k[0] != FPC_TKCLASS:
        return []
    nm = _sstr_raw(img, ti + 1)
    if nm is None:
        return []
    p = ti + 2 + nm[1] + 2 * ps
    un = _sstr_raw(img, p + 2)
    if un is None:
        return []
    q = p + 3 + un[1]
    n = _u16(img, q)
    if not n or n > MAX_PROPS:
        return []
    q += 2
    out: list[DlMethod] = []
    seen: set[tuple[str, int]] = set()
    for _ in range(n):
        got = _fpc_prop_info(img, q)
        if got is None:
            break
        name, get, set_, procs, size = got
        q += size
        for kind, w, mode in (("prop-get", get, procs & 3), ("prop-set", set_, (procs >> 2) & 3)):
            t: tuple[int, int] | None = None
            if mode == 1 and w and img.is_code(w):
                t = (w, -1)
            elif mode == 2 and w % ps == 0 and FPC_METHOD_START * ps <= w < MAX_VIRTUAL * ps:
                a = img.ptr(c.vmt + w)
                t = (a, w // ps - FPC_METHOD_START) if a and img.is_code(a) else None
            if t is not None and (kind, t[0]) not in seen:
                seen.add((kind, t[0]))
                out.append(DlMethod(kind, t[1], name, t[0]))
    return out


def _fpc_virtuals(img: Image, vmt: int, limit: int) -> list[DlMethod]:
    ps = img.psize
    out: list[DlMethod] = []
    for i in range(min(limit, MAX_VIRTUAL)):
        t = img.ptr(vmt + (FPC_METHOD_START + i) * ps)
        if t is None or not img.is_code(t):
            break
        out.append(DlMethod("virtual", i, "", t))
    return out


# Virtual slots of ``TObject`` (``objpash.inc``, ``TVmt``: ``vDestroy`` ... ``vToString``), FPC 3.x.
FPC_TOBJECT_VSLOTS = ("Destroy", "NewInstance", "FreeInstance", "SafeCallException", "DefaultHandler",
                      "AfterConstruction", "BeforeDestruction", "DefaultHandlerStr", "Dispatch", "DispatchStr",
                      "Equals", "GetHashCode", "ToString")
# ``TTypeKind`` of FPC 3.x for the managed field types of the init table
FPC_KIND_NAMES = {8: "LongString", 9: "AnsiString", 10: "WideString", 11: "Variant", 12: "array", 13: "record",
                  14: "interface", 15: "class", 16: "object", 21: "DynArray", 22: "interface", 24: "UnicodeString"}
FPC_COM_SLOTS = ("QueryInterface", "_AddRef", "_Release")
KNOWN_GUIDS = {"{00000000-0000-0000-C000-000000000046}": "IUnknown",
               "{00020400-0000-0000-C000-000000000046}": "IDispatch"}
MAX_INTF = 256


def _fpc_u32(img: Image, va: int) -> int | None:
    raw = img.read(va, 4)
    return struct.unpack("<I", raw)[0] if raw else None


def _fpc_messages(img: Image, tab: int) -> list[DlMethod]:
    """Integer message handlers (``vmtDynamicTable``): ``u32 count`` (pointer wide), then ``{u32 message id; ptr
    code}`` entries aligned to the pointer size. The name is the Windows / LCL message name when known."""
    from airlock.server.cpp import message_name
    ps = img.psize
    n = _fpc_u32(img, tab)
    if not n or n > MAX_PUBLISHED:
        return []
    out: list[DlMethod] = []
    for i in range(n):
        at = tab + ps + i * 2 * ps
        mid, code = _fpc_u32(img, at), img.ptr(at + ps)
        if mid is None or not code or not img.is_code(code):
            break
        out.append(DlMethod("message", mid, message_name(mid), code))
    return out


def _fpc_str_messages(img: Image, tab: int) -> list[DlMethod]:
    """String message handlers (``vmtMsgStrTable``): ``u32 count`` (pointer wide), then ``{ptr ShortString name;
    ptr code}``."""
    ps = img.psize
    n = _fpc_u32(img, tab)
    if not n or n > MAX_PUBLISHED:
        return []
    out: list[DlMethod] = []
    for i in range(n):
        at = tab + ps + i * 2 * ps
        np_, code = img.ptr(at), img.ptr(at + ps)
        name = _sstr(img, np_) if np_ else None
        if name is None or not code or not img.is_code(code):
            break
        out.append(DlMethod("message-str", i, name, code))
    return out


def _fpc_guid_text(img: Image, ref: int | None) -> str:
    raw = img.read(ref, 16) if ref else None
    if raw is None:
        return ""
    d1, d2, d3 = struct.unpack("<IHH", raw[:8])
    return "{%08X-%04X-%04X-%02X%02X-%s}" % (d1, d2, d3, raw[8], raw[9], raw[10:].hex().upper())


def _fpc_intf_entries(img: Image, tab: int) -> list[tuple[int, int, int, int, int]]:
    """Entries of an interface table: ``sizeuint count``, then ``{ptr ^GUID; ptr vtable; sizeuint IOffset; ptr
    ^ShortString GUID text; u32 IType}`` (20 bytes in 32-bit, 40 in 64-bit). Returns [(ref, vtable, offset,
    text ref, type)], [] when the table does not look like one."""
    ps = img.psize
    n = img.ptr(tab) if ps == 4 else _fpc_u32(img, tab)
    if not n or n > MAX_INTF:
        return []
    out = []
    for i in range(n):
        at = tab + ps + i * 5 * ps
        ref, vt, off, sref = img.ptr(at), img.ptr(at + ps), img.ptr(at + 2 * ps), img.ptr(at + 3 * ps)
        typ = _fpc_u32(img, at + 4 * ps)
        if vt is None or off is None or typ is None or typ > 8 or not img.in_image(vt):
            return []
        out.append((ref or 0, vt, off, sref or 0, typ))
    return out


FPC_TKINTERFACE = 14       # type kind of a COM interface (``tkInterface``)
MAX_INTF_CHAIN = 16


def _fpc_intf_typeinfo(img: Image, guid: bytes) -> int | None:
    """Type info (``tkInterface``) of the interface with this GUID: ``kind, ShortString name, ^parent, u8 flags,
    GUID``. The class tables point to no type info, so the GUID is searched in the data and the bytes before
    it are checked."""
    ps = img.psize
    if len(guid) != 16 or guid == bytes(16):
        return None
    for s in img.sections:
        if s.executable:
            continue
        i = s.data.find(guid)
        while i >= 0:
            at = s.va + i
            for ln in range(1, 65):
                ti = at - 1 - ps - ln - 2
                hdr = img.read(ti, 2)
                if hdr and hdr[0] == FPC_TKINTERFACE and hdr[1] == ln and _sstr(img, ti + 1) is not None:
                    return ti
            i = s.data.find(guid, i + 1)
    return None


def _fpc_intf_own(img: Image, ti: int) -> tuple[int, list[str], int | None] | None:
    """(method count, method names, parent type info) of the interface type info at ``ti`` (FPC 3.2:
    ``kind, name, ^^parent, flags, GUID, unit, TPropData, TIntfMethodTable``; FPC 3.0 has no method table, the
    count is then -1). A method entry is ``^^result, u8 cc, u8 kind, u16 params, sizeint stack, ^name``, then
    per parameter ``^^type, u16 flags, ^name, ^locs`` and ``^locs`` of the result."""
    ps = img.psize
    nm = _sstr_raw(img, ti + 1)
    if nm is None:
        return None
    p = ti + 2 + nm[1]
    cell = img.ptr(p)
    parent = img.ptr(cell) if cell else None
    un = _sstr_raw(img, p + ps + 17)
    if un is None:
        return None
    q = p + ps + 18 + un[1]
    n = _u16(img, q)
    if n is None or n > MAX_PROPS:
        return None
    q += 2
    for _ in range(n):
        got = _fpc_prop_info(img, q)
        if got is None:
            return None
        q += got[4]
    cnt, rcnt = _u16(img, q), _u16(img, q + 2)
    if cnt is None or rcnt is None or cnt > MAX_VIRTUAL:
        return None
    q += 4
    if rcnt == 0xFFFF:
        return cnt, [""] * cnt, parent
    names: list[str] = []
    for _ in range(cnt):
        res, head = img.ptr(q), img.read(q + ps, 4)
        np_ = img.ptr(q + 2 * ps + 4)
        name = _sstr(img, np_) if np_ else None
        if res is None or head is None or name is None:
            return None
        names.append(name)
        q += 3 * ps + 4 + struct.unpack("<H", head[2:4])[0] * (3 * ps + 2) + (ps if res else 0)
    return cnt, names, parent


def _fpc_intf_names(img: Image, guid: bytes) -> list[str]:
    """Method names of an interface by vtable slot (the parents' methods first), "" where unknown."""
    ti = _fpc_intf_typeinfo(img, guid)
    chain: list[list[str]] = []
    seen: set[int] = set()
    while ti and ti not in seen and len(chain) < MAX_INTF_CHAIN:
        seen.add(ti)
        k = img.read(ti, 1)
        got = _fpc_intf_own(img, ti) if k and k[0] == FPC_TKINTERFACE else None
        if got is None:
            break
        cnt, names, parent = got
        if cnt < 0:
            return []
        chain.append(names)
        ti = parent or 0
    out: list[str] = []
    for names in reversed(chain):
        out.extend(names)
    return out


# ``sub`` instructions in front of the ``jmp`` of an interface thunk: (opcode bytes, length)
_THUNK_PREFIXES = ((bytes([0x83, 0x6C, 0x24, 0x04]), 5), (bytes([0x81, 0x6C, 0x24, 0x04]), 8),   # sub [esp+4], n
                   (bytes([0x48, 0x83]), 4), (bytes([0x48, 0x81]), 7),                           # sub rcx, n
                   (bytes([0x83]), 3), (bytes([0x81]), 6), (bytes([0x2D]), 5))                   # sub eax, n


def _fpc_thunk_target(img: Image, addr: int) -> int | None:
    """Where an interface method thunk jumps: ``sub eax, off`` / ``sub [esp+4], off`` / ``sub rcx, off``, then
    ``jmp rel32``. A slot without a thunk (offset 0) is its own target."""
    b = img.read(addr, 16)
    if not b:
        return None
    i = 0
    for pat, size in _THUNK_PREFIXES:
        if b.startswith(pat):
            i = size
            break
    if b[i:i + 1] != bytes([0xE9]):
        return addr if i == 0 else None
    rel = struct.unpack("<i", b[i + 1:i + 5])[0]
    return (addr + i + 5 + rel) & ((1 << (8 * img.psize)) - 1)


def _fpc_interfaces(img: Image, entries: list[tuple[int, int, int, int, int]], vtables: set[int],
                    guid_names: dict[str, str], known: dict[int, str] | None = None
                    ) -> tuple[list[DlMethod], list[DlField]]:
    """Interfaces a class implements. Methods (kind ``interface``) are the code pointers of each interface
    vtable, named ``Interface.Method`` (``QueryInterface`` / ``_AddRef`` / ``_Release`` for the first three
    slots of a COM interface) or ``Interface.#n``; the field is the interface pointer at ``IOffset`` in the
    object. The interface is named from ``guid_names`` / ``KNOWN_GUIDS`` or is its GUID text. Other slots are named,
    in order, from the interface type info (FPC 3.2 with ``{$M+}``: method names), else from the class method the
    slot's thunk jumps to (``known``: {code address: name} of the class and its ancestors), else ``#n``."""
    ps = img.psize
    methods: list[DlMethod] = []
    fields: list[DlField] = []
    bounds = sorted(vtables)
    for ref, vt, off, sref, typ in entries:
        sp = img.ptr(sref) if sref else None
        text = (_sstr_raw(img, sp) or ("",))[0] if sp else ""
        guid = text if text.startswith("{") else _fpc_guid_text(img, img.ptr(ref) if ref else None)
        label = KNOWN_GUIDS.get(guid.upper(), "") or guid_names.get(guid.upper(), "") or guid or f"intf_{vt:x}"
        j = bisect_right(bounds, vt)
        stop = bounds[j] if j < len(bounds) else vt + MAX_VIRTUAL * ps
        slots: list[int] = []
        while vt + len(slots) * ps < stop and len(slots) < MAX_VIRTUAL:
            t = img.ptr(vt + len(slots) * ps)
            if t is None or not img.is_code(t):
                break
            slots.append(t)
        rtti = _fpc_intf_names(img, img.read(img.ptr(ref), 16) or b"") if ref and img.ptr(ref) else []
        if rtti and len(rtti) + 3 == len(slots):
            rtti = list(FPC_COM_SLOTS) + rtti
        if len(rtti) != len(slots):
            rtti = []
        for k, t in enumerate(slots):
            if ref and k < 3:
                nm = FPC_COM_SLOTS[k]
            else:
                tgt = _fpc_thunk_target(img, t)
                nm = rtti[k] if rtti else ""
                nm = nm or (known or {}).get(tgt if tgt is not None else -1, "") or f"#{k}"
            methods.append(DlMethod("interface", k, f"{label}.{nm}", t))
        if typ == 0:
            fields.append(DlField(label, off, "interface"))
    return methods, fields


def _fpc_init_fields(img: Image, c: DlClass, tab: int) -> list[DlField]:
    """Managed fields (strings, interfaces, dynamic arrays, variants) from the init table: ``kind, ShortString
    name``, then packed ``terminator ptr, i32 size, ptr, ptr, i32 count`` and ``{ptr ^typeinfo; sizeint offset}``
    entries (FPC 3.2 layout). The fields carry no name; the type is the kind of the field's type info."""
    ps = img.psize
    nm = _sstr_raw(img, tab + 1)
    if nm is None:
        return []
    p = tab + 2 + nm[1] + ps + 4 + 2 * ps
    n = _fpc_u32(img, p)
    if not n or n > MAX_PUBLISHED:
        return []
    out: list[DlField] = []
    for i in range(n):
        at = p + 4 + i * 2 * ps
        cell, off = img.ptr(at), img.ptr(at + ps)
        ti = img.ptr(cell) if cell else None
        kind = img.read(ti, 1) if ti else None
        if off is None or off >= max(c.size, 1) or not kind:
            return []
        out.append(DlField("", off, FPC_KIND_NAMES.get(kind[0], f"kind{kind[0]}")))
    return out


def _fpc_name_virtuals(by_vmt: dict[int, DlClass], vslots: dict[str, dict[int, str]] | None) -> None:
    """Names of the virtual methods a class introduces or overrides: ``TObject`` slots from ``FPC_TOBJECT_VSLOTS``,
    other classes from ``vslots`` ({introducing class name: {slot: method name}}, built from the symbols of
    reference programs, see ``fpcsigs``). An inherited slot (same code as the parent's) keeps no name."""
    for c in by_vmt.values():
        parent = by_vmt.get(c.parent_vmt)
        pcode = {m.slot: m.addr for m in parent.methods if m.kind == "virtual"} if parent else {}
        for m in c.methods:
            if m.kind != "virtual" or pcode.get(m.slot) == m.addr:
                continue
            cur, seen = c, set()
            while cur.vmt not in seen:                      # the class that introduced the slot
                seen.add(cur.vmt)
                up = by_vmt.get(cur.parent_vmt)
                if up is None or up.nvirtual <= m.slot:
                    break
                cur = up
            name = (vslots or {}).get(cur.name, {}).get(m.slot, "")
            if not name and cur.name == "TObject" and m.slot < len(FPC_TOBJECT_VSLOTS):
                name = FPC_TOBJECT_VSLOTS[m.slot]
            m.name = name


def parse_fpc_classes(img: Image, vslots: dict[str, dict[int, str]] | None = None,
                      guid_names: dict[str, str] | None = None) -> list[DlClass]:
    """All classes of a Free Pascal program, sorted by address. ``DlMethod.slot`` of a virtual method counts
    from the first virtual slot (0 = ``Destroy``). Also read: integer / string message handlers (kinds
    ``message``, ``message-str``), interface tables (kind ``interface`` methods, ``interface`` fields) and the
    managed fields of the init table (fields without a name). ``vslots`` / ``guid_names``: names from the
    signature build (``fpcsigs.load_names``). Not read: the automation table."""
    ps = img.psize
    intf: dict[int, list[tuple[int, int, int, int, int]]] = {}
    by_vmt: dict[int, DlClass] = {}
    for vmt in _fpc_scan(img):
        c = _fpc_read_class(img, vmt)
        if c is not None:
            by_vmt[vmt] = c
    order = sorted(by_vmt)
    for i, vmt in enumerate(order):
        c = by_vmt[vmt]
        cell = img.ptr(vmt + 2 * ps) or 0
        if cell:
            tgt = img.ptr(cell)
            pv = tgt if tgt in by_vmt else (cell if cell in by_vmt else 0)
            if pv and pv != vmt:
                c.parent_vmt = pv
                c.parent = by_vmt[pv].name
        c.unit = _unit_name(img, c.typeinfo, FPC_TKCLASS)
        mt = img.ptr(vmt + 5 * ps) or 0
        if mt:
            c.methods.extend(_fpc_published(img, mt))
        ft = img.ptr(vmt + 6 * ps) or 0
        if ft:
            c.fields = _fields(img, ft, by_vmt, first=1)
        named = {m.addr for m in c.methods}
        c.methods.extend(m for m in _fpc_properties(img, c) if m.addr not in named)
        nxt = order[i + 1] if i + 1 < len(order) else vmt + (FPC_METHOD_START + MAX_VIRTUAL) * ps
        c.methods.extend(_fpc_virtuals(img, vmt, max(0, (nxt - vmt) // ps - FPC_METHOD_START)))
        dt = img.ptr(vmt + 4 * ps) or 0
        if dt:
            c.methods.extend(_fpc_messages(img, dt))
        st = img.ptr(vmt + 11 * ps) or 0
        if st:
            c.methods.extend(_fpc_str_messages(img, st))
        it = img.ptr(vmt + 8 * ps) or 0
        if it:
            have = {f.offset for f in c.fields}
            c.fields.extend(f for f in _fpc_init_fields(img, c, it) if f.offset not in have)
        tab = img.ptr(vmt + 10 * ps) or 0
        if tab:
            intf[vmt] = _fpc_intf_entries(img, tab)
    vtables = {e[1] for ents in intf.values() for e in ents}
    _fpc_name_virtuals(by_vmt, vslots)
    for vmt, ents in intf.items():
        known = {m.addr: m.name for a in reversed(ancestors(by_vmt[vmt], by_vmt)) for m in a.methods
                 if m.name and m.kind in ("published", "virtual", "message-str")}
        ms, fs = _fpc_interfaces(img, ents, vtables, guid_names or {}, known)
        by_vmt[vmt].methods.extend(ms)
        by_vmt[vmt].fields.extend(fs)
    for c in by_vmt.values():             # a property whose accessor an ancestor already declares belongs to it
        up_p = {(m.kind, m.addr) for a in ancestors(c, by_vmt)[1:] for m in a.methods if m.kind in PROP_KINDS}
        if up_p:
            c.methods = [m for m in c.methods if m.kind not in PROP_KINDS or (m.kind, m.addr) not in up_p]
    return [by_vmt[v] for v in order]


def accessor_names(classes: list[DlClass]) -> dict[int, str]:
    """{address: ``Unit.Class.GetProp``} for the accessor methods that belong to one property of one class
    (a shared accessor, such as the abstract-method stub of several virtual properties or an indexed
    getter, is left out). The method name is the Delphi convention, not read from the program."""
    by: dict[int, set[tuple[str, str, str]]] = {}
    for c in classes:
        for m in c.methods:
            if m.kind in PROP_KINDS:
                by.setdefault(m.addr, set()).add((f"{c.unit}.{c.name}" if c.unit else c.name, m.kind, m.name))
    return {a: f"{cn}.{accessor_name(k, pn)}" for a, v in by.items() if len(v) == 1 for cn, k, pn in v}


def ancestors(c: DlClass, by_vmt: dict[int, DlClass]) -> list[DlClass]:
    """``c`` and its parents, nearest first (cycle safe)."""
    out: list[DlClass] = []
    seen: set[int] = set()
    cur: DlClass | None = c
    while cur is not None and cur.vmt not in seen:
        seen.add(cur.vmt)
        out.append(cur)
        cur = by_vmt.get(cur.parent_vmt)
    return out


# ── DFM ────────────────────────────────────────────────────────────────────

class DfmError(ValueError):
    pass


class Ident(str):
    """An identifier value (``OnClick = Button1Click``, ``Align = alClient``)."""


@dataclass
class Prop:
    name: str
    kind: str            # int | float | str | ident | bool | nil | set | list | binary | collection | currency | date
    value: Any


@dataclass
class Component:
    cls: str
    name: str
    flags: int = 0                      # 1 inherited, 2 child position, 4 inline
    props: list[Prop] = field(default_factory=list)
    children: list["Component"] = field(default_factory=list)

    @property
    def inherited(self) -> bool:
        return bool(self.flags & 1)

    @property
    def inline(self) -> bool:
        return bool(self.flags & 4)

    def prop(self, name: str) -> Prop | None:
        low = name.lower()
        for p in self.props:
            if p.name.lower() == low:
                return p
        return None

    @property
    def caption(self) -> str:
        for n in ("Caption", "Text", "Title", "Hint"):
            p = self.prop(n)
            if p is not None and p.kind == "str" and p.value:
                return str(p.value)
        return ""


VA_NULL, VA_LIST, VA_INT8, VA_INT16, VA_INT32, VA_EXTENDED, VA_STRING, VA_IDENT, VA_FALSE, VA_TRUE, \
    VA_BINARY, VA_SET, VA_LSTRING, VA_NIL, VA_COLLECTION, VA_SINGLE, VA_CURRENCY, VA_DATE, VA_WSTRING, \
    VA_INT64, VA_UTF8 = range(21)


class _R:
    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.d = data
        self.p = pos
        self.n = 0                       # components read

    def need(self, k: int) -> None:
        if self.p + k > len(self.d):
            raise DfmError("truncated")

    def u8(self) -> int:
        self.need(1)
        v = self.d[self.p]
        self.p += 1
        return v

    def peek(self) -> int:
        self.need(1)
        return self.d[self.p]

    def take(self, k: int) -> bytes:
        self.need(k)
        b = self.d[self.p:self.p + k]
        self.p += k
        return b

    def unpack(self, fmt: str) -> Any:
        sz = struct.calcsize(fmt)
        return struct.unpack(fmt, self.take(sz))[0]

    def sstr(self) -> str:
        return self.take(self.u8()).decode("latin-1")

    def text(self, raw: bytes) -> str:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("cp1252", "replace")


def _ext80(b: bytes) -> float:
    """x87 80-bit extended to float."""
    mant = int.from_bytes(b[:8], "little")
    se = int.from_bytes(b[8:10], "little")
    sign = -1.0 if se & 0x8000 else 1.0
    exp = se & 0x7FFF
    if exp == 0 and mant == 0:
        return 0.0
    if exp == 0x7FFF:
        return sign * float("inf") if mant << 1 & (2**64 - 1) == 0 else float("nan")
    try:
        return sign * mant * 2.0 ** (exp - 16383 - 63)
    except OverflowError:
        return sign * float("inf")


def _value(r: _R, depth: int = 0) -> tuple[str, Any]:
    if depth > MAX_DEPTH:
        raise DfmError("nesting")
    t = r.u8()
    if t == VA_NULL:
        return "nil", None
    if t == VA_LIST:
        items: list[Any] = []
        while r.peek() != VA_NULL:
            items.append(_value(r, depth + 1)[1])
        r.u8()
        return "list", items
    if t == VA_INT8:
        return "int", r.unpack("<b")
    if t == VA_INT16:
        return "int", r.unpack("<h")
    if t == VA_INT32:
        return "int", r.unpack("<i")
    if t == VA_INT64:
        return "int", r.unpack("<q")
    if t == VA_EXTENDED:
        return "float", _ext80(r.take(10))
    if t == VA_SINGLE:
        return "float", r.unpack("<f")
    if t == VA_CURRENCY:
        return "currency", r.unpack("<q") / 10000.0
    if t == VA_DATE:
        return "date", r.unpack("<d")
    if t == VA_STRING:
        return "str", r.text(r.take(r.u8()))
    if t == VA_LSTRING or t == VA_UTF8:
        return "str", r.text(r.take(r.unpack("<I")))
    if t == VA_WSTRING:
        n = r.unpack("<I")
        return "str", r.take(n * 2).decode("utf-16-le", "replace")
    if t == VA_IDENT:
        return "ident", Ident(r.take(r.u8()).decode("latin-1"))
    if t == VA_FALSE:
        return "bool", False
    if t == VA_TRUE:
        return "bool", True
    if t == VA_NIL:
        return "nil", None
    if t == VA_BINARY:
        return "binary", r.take(r.unpack("<I"))
    if t == VA_SET:
        items = []
        while True:
            s = r.sstr()
            if not s:
                break
            items.append(s)
        return "set", items
    if t == VA_COLLECTION:
        items = []
        while r.peek() != VA_NULL:
            if r.u8() != VA_LIST:
                raise DfmError("collection item")
            start = r.p
            try:                         # modern writers store no index; an integer first is an old-style index
                props = _props(r, depth + 1)
            except DfmError:
                if r.d[start] not in (VA_INT8, VA_INT16, VA_INT32):
                    raise
                r.p = start
                _value(r, depth + 1)
                props = _props(r, depth + 1)
            r.u8()                       # end of the item
            items.append(props)
        r.u8()
        return "collection", items
    raise DfmError(f"value type {t}")


def _props(r: _R, depth: int) -> list[Prop]:
    out: list[Prop] = []
    while r.peek() != 0:
        name = r.sstr()
        kind, val = _value(r, depth)
        out.append(Prop(name, kind, val))
    return out


def _component(r: _R, depth: int) -> Component:
    if depth > MAX_DEPTH or r.n > MAX_COMPONENTS:
        raise DfmError("too large")
    r.n += 1
    flags = 0
    if r.peek() >= 0xF0:
        flags = r.u8() & 0x0F
        if flags & 2:
            _value(r)                    # child position
    cls = r.sstr()
    name = r.sstr()
    comp = Component(cls, name, flags)
    comp.props = _props(r, depth + 1)
    r.u8()                               # end of the properties
    while r.peek() != 0:
        comp.children.append(_component(r, depth + 1))
    r.u8()                               # end of the children
    return comp


def parse_dfm(data: bytes) -> Component:
    """The component tree of a binary form resource (``TPF0`` + one root component). Raises DfmError."""
    if data[:4] != b"TPF0":
        raise DfmError("no TPF0 signature")
    try:
        return _component(_R(data, 4), 0)
    except (struct.error, IndexError) as e:
        raise DfmError(str(e)) from e


def walk(root: Component):
    """(seq, parent seq, depth, component) in document order, root first; ``seq`` is the index."""
    out: list[tuple[int, int, int, Component]] = []

    def go(c: Component, parent: int, depth: int) -> None:
        me = len(out)
        out.append((me, parent, depth, c))
        for ch in c.children:
            go(ch, me, depth + 1)
    go(root, -1, 0)
    return out


def is_event(p: Prop) -> bool:
    return p.kind == "ident" and len(p.name.split(".")[-1]) > 2 and p.name.split(".")[-1].startswith("On") \
        and p.name.split(".")[-1][2].isupper()


@dataclass
class Event:
    seq: int                 # component index in ``walk`` order
    prop: str
    handler: str
    owner: str               # class that must declare the handler (nearest inline component or the form)
    addr: int | None = None


def events_of(root: Component) -> list[Event]:
    """Event properties (``OnX = Handler``) of every component, with the class that owns the handler."""
    out: list[Event] = []
    rows = walk(root)
    scope: dict[int, str] = {}           # class that owns the children of a component
    for seq, parent, _d, c in rows:
        own = scope.get(parent, root.cls) if parent >= 0 else root.cls
        scope[seq] = c.cls if (c.inline and parent >= 0) else own
        for p in c.props:
            if is_event(p):
                out.append(Event(seq, p.name, str(p.value), own))
            elif p.kind == "collection":
                for i, item in enumerate(p.value):
                    for q in item:
                        if is_event(q):
                            out.append(Event(seq, f"{p.name}[{i}].{q.name}", str(q.value), own))
    return out


def resolve_handler(classes: list[DlClass], by_vmt: dict[int, DlClass], by_name: dict[str, DlClass],
                    owner: str, handler: str) -> tuple[int | None, str]:
    """(address, class that declares it) of the published method ``handler`` of class ``owner`` or the
    nearest ancestor. (None, '') when not found."""
    c = by_name.get(owner.lower())
    low = handler.lower()
    if c is not None:
        for a in ancestors(c, by_vmt):
            for m in a.methods:
                if m.kind == "published" and m.name.lower() == low:
                    return m.addr, a.name
    return None, ""


@dataclass
class Form:
    res_name: str
    root: Component
    events: list[Event]


def find_forms(pe: pefile.PE) -> list[Form]:
    out: list[Form] = []
    for e in peres.list_entries(pe):
        if e.type_id != 10:
            continue
        try:
            data = pe.get_data(e.rva, e.size)
        except Exception:  # noqa: BLE001  damaged entry
            continue
        if data[:4] != b"TPF0":
            continue
        try:
            root = parse_dfm(data)
        except DfmError as err:
            log.debug("DFM %s: %s", e.res_name, err)
            continue
        out.append(Form(str(e.res_name or e.res_id), root, events_of(root)))
    return out


# ── derivation ─────────────────────────────────────────────────────────────

SCHEMA_TABLES = ("dl_class", "dl_method", "dl_field", "dl_form", "dl_component", "dl_event")


def clear_binary(store: Store, binary_id: int) -> None:
    for t in SCHEMA_TABLES:
        store.db.execute(f"DELETE FROM {t} WHERE binary_id=?", (binary_id,))


def parse_file(path: Path, vslots: dict[str, dict[int, str]] | None = None,
               guid_names: dict[str, str] | None = None) -> tuple[list[DlClass], list[Form]] | None:
    """Classes and forms of a PE file; None when it is not a PE. ``vslots`` / ``guid_names``: Free Pascal names
    (``parse_classes``)."""
    img = Image.from_pe(path)
    if img is None:
        return None
    classes = parse_classes(img, vslots, guid_names)
    forms: list[Form] = []
    pe = peres.open_pe(path)
    if pe is not None:
        try:
            forms = find_forms(pe)
        finally:
            pe.close()
    by_vmt = {c.vmt: c for c in classes}
    by_name: dict[str, DlClass] = {}
    for c in classes:
        by_name.setdefault(c.name.lower(), c)
    for f in forms:
        for ev in f.events:
            ev.addr, _decl = resolve_handler(classes, by_vmt, by_name, ev.owner, ev.handler)
    return classes, forms


def store_rows(store: Store, binary_id: int, classes: list[DlClass], forms: list[Form]) -> None:
    db = store.db
    with db:
        clear_binary(store, binary_id)
        db.executemany(
            "INSERT OR REPLACE INTO dl_class(binary_id, vmt, name, parent_vmt, parent, size, unit, typeinfo, "
            "nvirtual) VALUES (?,?,?,?,?,?,?,?,?)",
            [(binary_id, c.vmt, c.name, c.parent_vmt or None, c.parent, c.size, c.unit, c.typeinfo or None,
              c.nvirtual) for c in classes])
        db.executemany(
            "INSERT INTO dl_method(binary_id, vmt, kind, slot, name, addr) VALUES (?,?,?,?,?,?)",
            [(binary_id, c.vmt, m.kind, m.slot, m.name, m.addr) for c in classes for m in c.methods])
        db.executemany(
            "INSERT INTO dl_field(binary_id, vmt, name, offset, type) VALUES (?,?,?,?,?)",
            [(binary_id, c.vmt, f.name, f.offset, f.type) for c in classes for f in c.fields])
        for f in forms:
            rows = walk(f.root)
            db.execute(
                "INSERT OR REPLACE INTO dl_form(binary_id, res_name, class, name, caption, ncomp, nevents, "
                "flags) VALUES (?,?,?,?,?,?,?,?)",
                (binary_id, f.res_name, f.root.cls, f.root.name, f.root.caption, len(rows), len(f.events),
                 "inherited" if f.root.inherited else ""))
            db.executemany(
                "INSERT OR REPLACE INTO dl_component(binary_id, form, seq, parent, depth, name, class, flags, "
                "caption) VALUES (?,?,?,?,?,?,?,?,?)",
                [(binary_id, f.res_name, s, p, d, c.name, c.cls,
                  ("inherited " if c.inherited else "") + ("inline" if c.inline else ""), c.caption)
                 for s, p, d, c in rows])
            db.executemany(
                "INSERT INTO dl_event(binary_id, form, seq, prop, handler, owner, addr) VALUES (?,?,?,?,?,?,?)",
                [(binary_id, f.res_name, e.seq, e.prop, e.handler, e.owner, e.addr) for e in f.events])
        store.set_meta(meta_key(binary_id), str(DELPHI_VERSION))


def derive_binary(store: Store, binary_id: int, artifact: Path,
                  names: tuple[dict[str, dict[int, str]], dict[str, str]] | None = None) -> tuple[int, int, int]:
    """Parse ``artifact`` and replace the Delphi rows of the binary. ``names``: (virtual slot names, interface
    names) of a Free Pascal build (``fpcsigs.load_names``). Returns (classes, forms, events)."""
    got = parse_file(artifact, *(names or (None, None)))
    if got is None:
        store_rows(store, binary_id, [], [])
        return 0, 0, 0
    classes, forms = got
    store_rows(store, binary_id, classes, forms)
    return len(classes), len(forms), sum(len(f.events) for f in forms)


def is_delphi(b: Binary) -> bool:
    """A Delphi or Free Pascal binary (the ``delphi_*`` tools read both)."""
    return b.toolchain in ("delphi", "fpc")


def is_fpc(b: Binary) -> bool:
    return b.toolchain == "fpc"


def stale(store: Store, binary_id: int) -> bool:
    return store.get_meta(meta_key(binary_id)) != str(DELPHI_VERSION)


NOT_GIVEN: Any = object()    # a caller that did not pass the configuration (None means: no folder configured)


def ensure(store: Store, binary: Binary, artifact: Path, idr_dir: Path | None = NOT_GIVEN,
           sig_dir: Path | None = NOT_GIVEN, warp_dir: Path | None = NOT_GIVEN) -> bool:
    """Derive the Delphi rows of a Delphi binary when missing or from an older DELPHI_VERSION, then the
    IDR names (``idr.ensure``; ``idr_dir`` is the knowledge base folder or None, ``sig_dir`` the folder of
    the signature databases, ``warp_dir`` the WARP libraries). Never raises; True
    when anything was (re)written. Other toolchains are not parsed."""
    if not is_delphi(binary) or not artifact.is_file():
        return False
    done = False
    names = tag = None
    given = not (idr_dir is NOT_GIVEN and sig_dir is NOT_GIVEN and warp_dir is NOT_GIVEN)
    # configuration not passed: keep the stored IDR and FPC names (None passed = really no folder: re-derive)
    fpc_names = is_fpc(binary) and sig_dir is not NOT_GIVEN
    if fpc_names:
        from airlock.server import fpcsigs
        names, tag = fpcsigs.load_names(None if sig_dir is NOT_GIVEN else sig_dir, binary.toolchain_ver or "")
    if stale(store, binary.id) or (fpc_names and store.get_meta(f"delphi_names:{binary.id}") != tag):
        try:
            derive_binary(store, binary.id, artifact, names)
            if fpc_names:
                with store.db:
                    store.set_meta(f"delphi_names:{binary.id}", tag)
            done = True
        except Exception as e:  # noqa: BLE001  an extra; the binary stays usable
            log.warning("Delphi analysis of %s failed: %s", binary.name, e)
            return False
    from airlock.server import idr
    if not given:
        return done
    none = lambda v: None if v is NOT_GIVEN else v  # noqa: E731
    return idr.ensure(store, binary, artifact, none(idr_dir), none(sig_dir), none(warp_dir)) or done


def ensure_project(store: Store, artifacts: Path, idr_dir: Path | None = None, sig_dir: Path | None = None,
                   warp_dir: Path | None = None) -> int:
    n = 0
    for b in store.list_binaries():
        if store.get_meta(f"status:{b.id}") == "ready" and ensure(store, b, artifacts / b.sha256, idr_dir, sig_dir, warp_dir):
            n += 1
    return n


# ── name hints ─────────────────────────────────────────────────────────────

def _fpc_table_hint(cls: str, kind: str, slot: int, name: str) -> str:
    """Hint for a Free Pascal message handler or interface method (``dl_method`` kinds of ``parse_fpc_classes``)."""
    if kind == "message":
        return f"message handler {name} (0x{slot:x}) of {cls}"
    if kind == "message-str":
        return f"message handler '{name}' of {cls}"
    return f"{name} (interface slot {slot}) of {cls}"


def hints_for(store: Store, binary_id: int, entry: int) -> list[str]:
    """Hints for a function entry: ``Class.Method`` (published), ``handler OnClick of Button1 (TButton
    "OK") in form TMainForm`` (DFM event) and ``Class::vslot N`` (virtual method)."""
    out: list[str] = []
    q = store.db.execute
    pub = q("SELECT c.name, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
            "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.kind='published' ORDER BY c.vmt LIMIT 2",
            (binary_id, entry)).fetchall()
    for r in pub:
        out.append(f"{r[0]}.{r[1]} (published)")
    seen = {(r[0], r[1]) for r in pub}
    for r in q("SELECT c.unit, c.name, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
               "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.kind LIKE 'rtti-%' ORDER BY c.vmt LIMIT 3",
               (binary_id, entry)):
        if (r[1], r[2]) not in seen:
            seen.add((r[1], r[2]))
            out.append(f"rtti: {r[0] + '.' if r[0] else ''}{r[1]}.{r[2]}")
    out.extend(_event_hints(q("SELECT e.prop, c.name, c.class, c.caption, f.class FROM dl_event e JOIN dl_form f ON "
                              "f.binary_id=e.binary_id AND f.res_name=e.form JOIN dl_component c ON "
                              "c.binary_id=e.binary_id AND c.form=e.form AND c.seq=e.seq WHERE e.binary_id=? "
                              "AND e.addr=? ORDER BY e.form, e.seq", (binary_id, entry)).fetchall()))
    props = q("SELECT c.unit, c.name, m.kind, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
              "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.kind IN ('prop-get','prop-set') "
              "ORDER BY c.vmt, m.name LIMIT 3", (binary_id, entry)).fetchall()
    for r in props:
        out.append(f"prop: {r[0] + '.' if r[0] else ''}{r[1]}.{accessor_name(r[2], r[3])} "
                   f"({'getter' if r[2] == 'prop-get' else 'setter'} of {r[3]}, name by convention)")
    for r in q("SELECT c.name, m.kind, m.slot, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id "
               "AND c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.kind IN ('message', 'message-str', "
               "'interface') ORDER BY c.vmt, m.kind, m.slot LIMIT 4", (binary_id, entry)):
        out.append(_fpc_table_hint(r[0], r[1], r[2], r[3]))
    by_slot: dict[int, list[str]] = {}
    slot_name: dict[int, str] = {}
    for r in q("SELECT c.name, m.slot, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
               "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.kind='virtual' ORDER BY m.slot, c.vmt",
               (binary_id, entry)):
        names = by_slot.setdefault(r[1], [])
        if r[0] not in names:
            names.append(r[0])
        if r[2]:
            slot_name.setdefault(r[1], r[2])
    for slot, names in list(by_slot.items())[:3]:
        extra = f" (+{len(names) - 1} classes)" if len(names) > 1 else ""
        label = f" ({slot_name[slot]})" if slot in slot_name else ""
        out.append(f"{names[0]}::vslot {slot}{label}{extra}")
    from airlock.server import idr
    out.extend(idr.hint_for(store, binary_id, entry))
    return out


_EVENT_SHOWN = 24      # bindings named per (event, class, form) group; the rest are counted


def _event_hints(rows) -> list[str]:
    """DFM bindings of one handler, every one of them: a single binding as ``handler OnClick of Button1
    (TButton "OK") in form TMainForm``, several components of one class sharing the handler (one
    ``actFlushExecute`` for six actions) as ``handler OnExecute of 6 TAction: actA "A", actB "B" in form
    TMainForm`` so that no binding is dropped."""
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r[0], r[2], r[4], bool(r[1])), []).append(r)
    out: list[str] = []
    for (prop, cls, form, named), rs in groups.items():
        if len(rs) == 1 or not named:
            for r in rs:
                cap = f' "{_short(r[3])}"' if r[3] else ""
                who = f"{r[1]} ({r[2]}{cap})" if r[1] else f"form ({r[2]})"
                out.append(f"handler {prop} of {who} in form {form}")
            continue
        items = [f'{r[1]} "{_short(r[3])}"' if r[3] else r[1] for r in rs[:_EVENT_SHOWN]]
        more = f", +{len(rs) - _EVENT_SHOWN} more" if len(rs) > _EVENT_SHOWN else ""
        out.append(f"handler {prop} of {len(rs)} {cls}: {', '.join(items)}{more} in form {form}")
    return out


def _short(text: str, n: int = 40) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= n else text[:n - 1] + "…"


# ── UI line and feature seeds ──────────────────────────────────────────────

_MENU_CLASSES = ("menuitem", "action", "popupmenu")


def ui_line(store: Store, binary_id: int) -> str:
    """One line for the project map: ``UI: 12 Delphi forms, 85 events (70 mapped to handlers)``; empty
    for a binary without DFM forms."""
    try:
        r = store.db.execute("SELECT COUNT(*) FROM dl_form WHERE binary_id=?", (binary_id,)).fetchone()
        if not r[0]:
            return ""
        e = store.db.execute("SELECT COUNT(*), COUNT(addr), COUNT(DISTINCT addr) FROM dl_event "
                             "WHERE binary_id=?", (binary_id,)).fetchone()
    except Exception:  # noqa: BLE001  an extra
        return ""
    return f"UI: {r[0]} Delphi forms; events {e[0]}, mapped to handlers {e[1]} ({e[2]} functions)"


def feature_seeds(store: Store, binary_id: int) -> list[tuple[int, str, str]]:
    """(handler address, feature key, evidence) for DFM events with a resolved handler: menu items and
    actions seed ``ui-menu``, the other components ``ui-dialog``."""
    out: list[tuple[int, str, str]] = []
    for r in store.db.execute(
            "SELECT e.addr, e.prop, e.handler, c.name, c.class, c.caption, f.class AS fclass FROM dl_event e "
            "JOIN dl_component c ON c.binary_id=e.binary_id AND c.form=e.form AND c.seq=e.seq "
            "JOIN dl_form f ON f.binary_id=e.binary_id AND f.res_name=e.form "
            "WHERE e.binary_id=? AND e.addr IS NOT NULL ORDER BY e.form, e.seq, e.prop", (binary_id,)):
        cls = (r["class"] or "").lower()
        menu = any(cls.endswith(s) for s in _MENU_CLASSES)
        cap = f' "{_short(r["caption"])}"' if r["caption"] else ""
        what = f"{r['fclass']}.{r['name'] or 'form'}{cap} {r['prop']}"
        out.append((r["addr"], "ui-menu" if menu else "ui-dialog", what))
    return out


# ── runtime recognition ────────────────────────────────────────────────────

# Units of the RTL / VCL / FMX and common component libraries (the full name or the first dotted part).
RUNTIME_UNITS = frozenset(
    "system sysinit sysutils classes types typinfo variants varutils math strutils dateutils ioutils "
    "contnrs syncobjs rtlconsts character generics inifiles registry windows winapi messages wintypes "
    "winprocs shellapi shlobj comobj comserv activex olectrls ole2 oleauto oleconst stdvcl "
    "controls forms graphics stdctrls extctrls dialogs menus buttons comctrls actnlist imglist "
    "clipbrd printers grids dbgrids db dbctrls dbtables adodb datasnap midas sqlexpr "
    "vcl fmx data xml soap web rest system.generics idglobal idcomponent idtcpclient idtcpserver "
    "idhttp idsockethandle idstack idcustomtcpserver idiohandler idexception "
    # Free Pascal RTL and Lazarus LCL
    "objpas strings sysconst widestrings fgl ctypes dynlibs lcl lclproc lcltype lclintf lclstrconsts lclclasses "
    "lmessages lresources lcltranslator interfaces interfacebase graphtype fpimage intfgraphics lazutf8 "
    "lazfileutils lazutils lazloggerbase lazlogger lazmethodlist customtimer extdlgs spin checklst colorbox "
    "arrow calendar maskedit editbtn".split())
_UNIT_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")


_DOTTED_RUNTIME = ("system", "vcl", "winapi", "fmx", "data", "xml", "soap", "web", "rest")


def runtime_unit(unit: str) -> bool:
    """True for a unit of the Delphi runtime or a common component library (``System.Classes``,
    ``Vcl.Forms``, ``SysUtils``, ``Controls``). A program's own units are not."""
    u = unit.strip().lower()
    if not u or not _UNIT_RE.match(u):
        return False
    if u in RUNTIME_UNITS:
        return True
    head, dot, _rest = u.partition(".")
    return bool(dot) and head in _DOTTED_RUNTIME


_AT_SUFFIX = re.compile(r"@\d+$")


def runtime_name(name: str, ns: str | None) -> bool:
    """A Delphi runtime name: ``@LStrAsg`` / ``@HandleFinally`` style helpers (an ``@`` prefix; MSVC
    ``@name@4`` decorations and ``@_`` names are not), or a namespace that is a runtime unit."""
    if name.startswith("@") and len(name) > 1 and not name.startswith("@_") and not _AT_SUFFIX.search(name):
        return True
    if ns:
        top = ns.split("::", 1)[0]
        if top.lower() in ("system", "sysutils", "classes") or top.split(".", 1)[0].lower() in ("vcl", "winapi", "fmx"):
            return True
    return False


def runtime_addrs(store: Store, binary_id: int) -> set[int]:
    """Addresses of published and virtual methods of classes declared in runtime units, and of the
    functions named from an IDR knowledge base (RTL / VCL code by definition)."""
    from airlock.server import idr
    out: set[int] = idr.hit_addrs(store, binary_id)
    cache: dict[str, bool] = {}
    for unit, addr in store.db.execute(
            "SELECT c.unit, m.addr FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
            "c.vmt=m.vmt WHERE m.binary_id=? AND c.unit<>''", (binary_id,)):
        ok = cache.get(unit)
        if ok is None:
            ok = cache[unit] = runtime_unit(unit)
        if ok:
            out.add(addr)
    return out
