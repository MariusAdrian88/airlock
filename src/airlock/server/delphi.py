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
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pefile

from airlock.index.store import Binary, Store
from airlock.server import peres
from airlock.server.cpp import Image

log = logging.getLogger("airlock")

DELPHI_VERSION = 2
DELPHI_META = "delphi_version"     # meta key prefix; the full key is ``delphi_version:<binary id>``

MAX_VIRTUAL = 1024                 # virtual method slots read per class
MAX_PUBLISHED = 4096
MAX_RTTI = 16384                   # extended method entries read per class
MAX_COMPONENTS = 20000             # per form
MAX_DEPTH = 64
MIN_SLOTS, MAX_SLOTS = 19, 32      # slots before the class reference (22 in 32-bit Delphi 2009+, 19 older)

_IDENT = re.compile(r"^[A-Za-z_][\w.<>,$&+ \[\]]*$")


def meta_key(binary_id: int) -> str:
    return f"{DELPHI_META}:{binary_id}"


# ── classes ────────────────────────────────────────────────────────────────

@dataclass
class DlMethod:
    kind: str            # published | virtual | rtti-private | rtti-protected | rtti-public | rtti-published
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


def _unit_name(img: Image, ti: int) -> str:
    if not ti:
        return ""
    ps = img.psize
    k = img.read(ti, 1)
    if not k or k[0] != 7:
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


def _fields(img: Image, tab: int, by_vmt: dict[int, DlClass]) -> list[DlField]:
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
            if ctab and ti < ncls:
                cell = img.ptr(ctab + 2 + ti * ps)
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


def parse_classes(img: Image) -> list[DlClass]:
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
        nxt = order[i + 1] - found[order[i + 1]][1] * ps if i + 1 < len(order) else vmt + MAX_VIRTUAL * ps
        c.methods.extend(_virtuals(img, vmt, max(0, (nxt - vmt) // ps)))
    for c in by_vmt.values():             # a method that a parent already names belongs to the parent
        if not any(m.kind.startswith("rtti") for m in c.methods):
            continue
        up = {(m.name, m.addr) for a in ancestors(c, by_vmt)[1:] for m in a.methods if m.kind != "virtual"}
        if up:
            c.methods = [m for m in c.methods if m.kind == "virtual" or (m.name, m.addr) not in up]
    return [found[v][0] for v in order]


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


def parse_file(path: Path) -> tuple[list[DlClass], list[Form]] | None:
    """Classes and forms of a PE file; None when it is not a PE."""
    img = Image.from_pe(path)
    if img is None:
        return None
    classes = parse_classes(img)
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


def derive_binary(store: Store, binary_id: int, artifact: Path) -> tuple[int, int, int]:
    """Parse ``artifact`` and replace the Delphi rows of the binary. Returns (classes, forms, events)."""
    got = parse_file(artifact)
    if got is None:
        store_rows(store, binary_id, [], [])
        return 0, 0, 0
    classes, forms = got
    store_rows(store, binary_id, classes, forms)
    return len(classes), len(forms), sum(len(f.events) for f in forms)


def is_delphi(b: Binary) -> bool:
    return b.toolchain == "delphi"


def stale(store: Store, binary_id: int) -> bool:
    return store.get_meta(meta_key(binary_id)) != str(DELPHI_VERSION)


def ensure(store: Store, binary: Binary, artifact: Path, idr_dir: Path | None = None,
           sig_dir: Path | None = None, warp_dir: Path | None = None) -> bool:
    """Derive the Delphi rows of a Delphi binary when missing or from an older DELPHI_VERSION, then the
    IDR names (``idr.ensure``; ``idr_dir`` is the knowledge base folder or None, ``sig_dir`` the folder of
    the signature databases, ``warp_dir`` the WARP libraries). Never raises; True
    when anything was (re)written. Other toolchains are not parsed."""
    if not is_delphi(binary) or not artifact.is_file():
        return False
    done = False
    if stale(store, binary.id):
        try:
            derive_binary(store, binary.id, artifact)
            done = True
        except Exception as e:  # noqa: BLE001  an extra; the binary stays usable
            log.warning("Delphi analysis of %s failed: %s", binary.name, e)
            return False
    from airlock.server import idr
    return idr.ensure(store, binary, artifact, idr_dir, sig_dir, warp_dir) or done


def ensure_project(store: Store, artifacts: Path, idr_dir: Path | None = None, sig_dir: Path | None = None,
                   warp_dir: Path | None = None) -> int:
    n = 0
    for b in store.list_binaries():
        if store.get_meta(f"status:{b.id}") == "ready" and ensure(store, b, artifacts / b.sha256, idr_dir, sig_dir, warp_dir):
            n += 1
    return n


# ── name hints ─────────────────────────────────────────────────────────────

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
    ev = q("SELECT e.prop, c.name, c.class, c.caption, f.class FROM dl_event e JOIN dl_form f ON "
           "f.binary_id=e.binary_id AND f.res_name=e.form JOIN dl_component c ON c.binary_id=e.binary_id AND "
           "c.form=e.form AND c.seq=e.seq WHERE e.binary_id=? AND e.addr=? ORDER BY e.form, e.seq LIMIT 4",
           (binary_id, entry)).fetchall()
    for r in ev:
        cap = f' "{_short(r[3])}"' if r[3] else ""
        who = f"{r[1]} ({r[2]}{cap})" if r[1] else f"form ({r[2]})"
        out.append(f"handler {r[0]} of {who} in form {r[4]}")
    by_slot: dict[int, list[str]] = {}
    for r in q("SELECT c.name, m.slot FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
               "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.kind='virtual' ORDER BY m.slot, c.vmt",
               (binary_id, entry)):
        names = by_slot.setdefault(r[1], [])
        if r[0] not in names:
            names.append(r[0])
    for slot, names in list(by_slot.items())[:3]:
        extra = f" (+{len(names) - 1} classes)" if len(names) > 1 else ""
        out.append(f"{names[0]}::vslot {slot}{extra}")
    from airlock.server import idr
    out.extend(idr.hint_for(store, binary_id, entry))
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
    "idhttp idsockethandle idstack idcustomtcpserver idiohandler idexception".split())
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
