"""Qt metaobjects (``QMetaObject``) parsed from the PE bytes (DESIGN 11 "Qt metaobjects").

No worker and no Ghidra for the tables: ``Image`` (server/cpp.py) maps the sections of the stored artifact, the
scan finds every ``staticMetaObject`` and ``derive_binary`` writes ``qt_class``, ``qt_method``, ``qt_prop``,
``qt_enum`` (schema v13). What needs code (the function behind each method index, the superclass when it
lives in another DLL) is resolved by the worker op ``qt_dispatch`` (``worker/ghidra_ops/qt.py``) and stored
back by ``store_dispatch``. String-based ``connect`` calls are joined from the string and edge tables.

Layouts, all little endian, ``P`` = pointer size. See DESIGN 11 for what is verified.

* ``QMetaObject::d`` Qt5: ``superdata, stringdata, data, static_metacall, relatedMetaObjects, extradata``
  (6 pointers). Qt6: ``superdata, stringdata, data, static_metacall, relatedMetaObjects, metaTypes,
  extradata`` (7 pointers). ``superdata`` is 0 in the file when the parent class lives in another DLL
  (the compiler initialises it at start-up).
* ``data`` (uint array): ``revision, className, classInfoCount, classInfoData, methodCount, methodData,
  propertyCount, propertyData, enumCount, enumData, constructorCount, constructorData, flags,
  signalCount`` (14 words). Revision 7 and 8 are Qt5, 9 and above Qt6.
* method: ``name, argc, parameters, tag, flags`` (5 words; Qt6 adds ``initial metatype offset``).
  ``parameters`` points at ``returnType, argc types, argc names``; a type with bit 31 set is a string
  index, otherwise a ``QMetaType`` id. The first ``signalCount`` methods are signals.
* property: ``name, type, flags`` (3 words; Qt6: ``name, type, flags, notifyId, revision``). In Qt5 an
  array of ``propertyCount`` notify signal ids follows the table when any property has the Notify flag.
* enum: ``name, flags, count, data`` (4 words; 5 with an ``alias`` word from revision 8), the
  enumerators at ``data`` are ``name, value`` pairs.
* Qt5 string data: ``QByteArrayData[]``, each ``ref (-1), size, alloc, offset`` (16 bytes in 32-bit, 24 in
  64-bit); the text is at ``item address + offset``. Qt6 (moc since 6.4): ``uint offsetsAndSizes[]`` pairs
  ``offset, size`` with the offset relative to the start of the array.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.index.store import Binary, Store
from airlock.server.cpp import Image

log = logging.getLogger("airlock")

QT_VERSION = 3   # 3: Itanium import names, string connects with the import loaded into a register; 2: Qt6 SuperData getter layout, Qt6 notify ids, C++ import rows, connect call sites through import slots
QT_META = "qt_version"             # meta key prefix; the full key is ``qt_version:<binary id>``
DISPATCH_VERSION = 3   # 3: connectImpl calls through a register, 32-bit and Itanium shapes; 2: pointer-to-member connects (worker op qt_connects)
DISPATCH_META = "qt_dispatch"      # set when the worker op ran (``qt_dispatch:<binary id>``)

HEADER_WORDS = 14
MAX_METHODS = 8192
MAX_PROPS = 4096
MAX_ENUMS = 1024
MAX_STRING = 2048
MIN_REV, MAX_REV = 7, 16


def meta_key(binary_id: int) -> str:
    return f"{QT_META}:{binary_id}"


def dispatch_key(binary_id: int) -> str:
    return f"{DISPATCH_META}:{binary_id}"


# QMetaType ids that moc writes into method and property type slots.
TYPE_NAMES = {
    1: "bool", 2: "int", 3: "uint", 4: "qlonglong", 5: "qulonglong", 6: "double", 7: "QChar",
    8: "QVariantMap", 9: "QVariantList", 10: "QString", 11: "QStringList", 12: "QByteArray",
    13: "QBitArray", 14: "QDate", 15: "QTime", 16: "QDateTime", 17: "QUrl", 18: "QLocale", 19: "QRect",
    20: "QRectF", 21: "QSize", 22: "QSizeF", 23: "QLine", 24: "QLineF", 25: "QPoint", 26: "QPointF",
    27: "QRegExp", 28: "QVariantHash", 29: "QEasingCurve", 30: "QUuid", 31: "void*", 32: "long",
    33: "short", 34: "char", 35: "ulong", 36: "ushort", 37: "uchar", 38: "float", 39: "QObject*",
    40: "signed char", 41: "QVariant", 42: "QModelIndex", 43: "void", 44: "QRegularExpression",
    45: "QJsonValue", 46: "QJsonObject", 47: "QJsonArray", 48: "QJsonDocument", 49: "QCborValue",
    50: "QCborArray", 51: "QCborMap", 52: "QCborSimpleType", 53: "QPersistentModelIndex",
    54: "nullptr_t", 55: "QCborTag", 56: "QByteArrayList",
    64: "QFont", 65: "QPixmap", 66: "QBrush", 67: "QColor", 68: "QPalette", 69: "QIcon", 70: "QImage",
    71: "QPolygon", 72: "QRegion", 73: "QBitmap", 74: "QCursor", 75: "QKeySequence", 76: "QPen",
    77: "QTextLength", 78: "QTextFormat", 79: "QMatrix", 80: "QTransform", 81: "QMatrix4x4",
    82: "QVector2D", 83: "QVector3D", 84: "QVector4D", 85: "QQuaternion", 86: "QPolygonF",
    121: "QSizePolicy",
}

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")
_ACCESS = {0: "private", 1: "protected", 2: "public", 3: ""}
_KIND = {0: "method", 4: "signal", 8: "slot", 12: "constructor"}
PROP_NOTIFY = 0x00400000
PROP_ENUM = 0x8
PROP_REVISIONED = 0x00800000


# ── rows ───────────────────────────────────────────────────────────────────

@dataclass
class QtMethod:
    idx: int
    kind: str                       # signal | slot | method | constructor
    name: str
    ret: str = ""
    params: list[tuple[str, str]] = field(default_factory=list)    # (type, parameter name)
    access: str = ""
    flags: int = 0
    addr: int | None = None

    @property
    def cloned(self) -> bool:
        return bool(self.flags & 0x20)

    def arg_types(self) -> str:
        return ",".join(t for t, _ in self.params)

    def signature(self) -> str:
        """``name(T1,T2)``: the form of a SIGNAL() / SLOT() string."""
        return f"{self.name}({self.arg_types()})"


@dataclass
class QtProp:
    idx: int
    name: str
    type: str
    flags: int
    notify: int | None = None       # signal index in the class


@dataclass
class QtEnum:
    idx: int
    name: str
    is_flag: bool
    values: list[tuple[str, int]]


@dataclass
class QtClass:
    meta: int                       # address of staticMetaObject
    name: str
    major: int
    revision: int
    super_addr: int | None
    data_addr: int
    metacall: int | None
    nsignals: int
    methods: list[QtMethod] = field(default_factory=list)
    props: list[QtProp] = field(default_factory=list)
    enums: list[QtEnum] = field(default_factory=list)
    ctors: list[QtMethod] = field(default_factory=list)
    info: list[tuple[str, str]] = field(default_factory=list)
    parent: str = ""


# ── string data ────────────────────────────────────────────────────────────

class _Strings:
    """The string table of one metaobject (either layout)."""

    def __init__(self, img: Image, base: int, mode: str) -> None:
        self.img, self.base, self.mode = img, base, mode
        self.isz = 16 if img.psize == 4 else 24
        self.off_at = 12 if img.psize == 4 else 16

    def get(self, idx: int) -> str | None:
        img = self.img
        if idx < 0 or idx > 200000:
            return None
        if self.mode == "table":                 # Qt5 and Qt6 up to 6.3: QByteArrayData[]
            item = self.base + idx * self.isz
            b = img.read(item, self.isz)
            if b is None or struct.unpack_from("<i", b, 0)[0] != -1:
                return None
            size = struct.unpack_from("<i", b, 4)[0]
            off = struct.unpack_from("<i" if img.psize == 4 else "<q", b, self.off_at)[0]
            addr = item + off
        else:                                    # offsetsAndSizes
            b = img.read(self.base + 8 * idx, 8)
            if b is None:
                return None
            off, size = struct.unpack("<II", b)
            addr = self.base + off
        if size < 0 or size > MAX_STRING:
            return None
        raw = img.read(addr, size + 1)
        if raw is None or raw[size:size + 1] != b"\0":
            return None
        return raw[:size].decode("utf-8", "replace")


def _strings_for(img: Image, base: int, name_idx: int) -> _Strings | None:
    for mode in ("table", "offsets"):
        s = _Strings(img, base, mode)
        n = s.get(name_idx)
        if n and _IDENT.match(n):
            return s
    return None


# ── scan ───────────────────────────────────────────────────────────────────

def _words(img: Image, addr: int, n: int) -> list[int] | None:
    """``n`` uints at ``addr``; fewer when the section ends earlier (at least the header)."""
    sec = img.section_at(addr)
    if sec is None:
        return None
    avail = (min(sec.end, sec.va + len(sec.data)) - addr) // 4
    n = min(n, avail)
    if n < HEADER_WORDS:
        return None
    b = img.read(addr, n * 4)
    return list(struct.unpack(f"<{n}I", b)) if b is not None else None


def _plausible_header(h: list[int]) -> bool:
    rev = h[0]
    if not MIN_REV <= rev <= MAX_REV:
        return False
    # (count, offset) pairs: classInfo, methods, properties, enums, constructors
    for i in (2, 4, 6, 8, 10):
        cnt, off = h[i], h[i + 1]
        if cnt > MAX_METHODS or off > 0x100000 or (cnt and off < HEADER_WORDS):
            return False
    if h[13] > h[5 - 1] and h[13] > MAX_METHODS:       # signalCount
        return False
    return h[13] <= h[4]


def _candidates(img: Image) -> list[tuple[int, int, int, int, int, int, int | None]]:
    """(meta address, superdata, stringdata, data, static_metacall, related, metaTypes|None)."""
    ps = img.psize
    lo = min(s.va for s in img.sections)
    hi = max(s.end for s in img.sections)
    out = []
    for sva, words in img.data_words(ps):
        n = len(words)
        for i in range(n - 5):
            s = words[i + 1]
            if not lo <= s < hi:
                continue
            d = words[i + 2]
            if not lo <= d < hi:
                continue
            sec = img.section_at(d)
            if sec is None or sec.executable:
                continue
            b = img.read(d, HEADER_WORDS * 4)
            if b is None:
                continue
            h = struct.unpack("<%dI" % HEADER_WORDS, b)
            if not _plausible_header(list(h)):
                continue
            mc = words[i + 3]
            if mc and not img.is_code(mc):
                continue
            rel = words[i + 4]
            sup = words[i]
            major6 = h[0] >= 9
            meta_types = words[i + 5] if major6 and i + 5 < n else None
            out.append((sva + i * ps, sup, s, d, mc, rel, meta_types))
    return out


def _type_name(strings: _Strings, word: int) -> str:
    if word & 0x80000000:
        return strings.get(word & 0x7FFFFFFF) or "?"
    return TYPE_NAMES.get(word & 0x3FFFFFFF if word >= 0x10000 else word, f"type#{word}")


def _decode(img: Image, cand: tuple) -> QtClass | None:
    meta, sup, sbase, dbase, mc, _rel, _mt = cand
    h = _words(img, dbase, HEADER_WORDS)
    if h is None:
        return None
    rev = h[0]
    major = 6 if rev >= 9 else 5
    strings = _strings_for(img, sbase, h[1])
    if strings is None:
        return None
    name = strings.get(h[1]) or ""
    mcount, moff = h[4], h[5]
    pcount, poff = h[6], h[7]
    ecount, eoff = h[8], h[9]
    ccount, coff = h[10], h[11]
    icount, ioff = h[2], h[3]
    need = max(HEADER_WORDS, ioff + 2 * icount, moff + 6 * (mcount + ccount) + 8, poff + 5 * pcount + 2 * pcount,
               eoff + 5 * ecount, coff + 6 * ccount)
    # parameter blocks sit behind the tables: read generously, bounded by the section
    w = _words(img, dbase, min(need + 4096 + 16 * (mcount + ccount), 0x40000))
    if w is None:
        return None
    mw = 6 if major == 6 else 5
    ew = 5 if rev >= 8 else 4
    pw = 5 if major == 6 else 3

    def at(i: int) -> int:
        return w[i] if 0 <= i < len(w) else 0

    def method(i: int, base: int, ctor: bool) -> QtMethod:
        p = base + i * mw
        flags = at(p + 4)
        kind = _KIND.get(flags & 0x0C, "method")
        argc = at(p + 1)
        pr = at(p + 2)
        ret = ""
        params: list[tuple[str, str]] = []
        if argc <= 64 and pr + 1 + 2 * argc <= len(w):
            ret = _type_name(strings, at(pr)) if not ctor else ""
            for k in range(argc):
                tn = _type_name(strings, at(pr + 1 + k))
                pn = strings.get(at(pr + 1 + argc + k)) or ""
                params.append((tn, pn))
        return QtMethod(i, kind, strings.get(at(p)) or "?", ret, params, _ACCESS.get(flags & 3, ""), flags)

    c = QtClass(meta, name, major, rev, sup or None, dbase, mc or None, h[13])
    if mcount > MAX_METHODS or pcount > MAX_PROPS or ecount > MAX_ENUMS or icount > 1024:
        return None
    for i in range(icount):
        k, v = strings.get(at(ioff + 2 * i)), strings.get(at(ioff + 2 * i + 1))
        c.info.append((k or "?", v or ""))
    for i in range(mcount):
        m = method(i, moff, False)
        if i < h[13]:
            m.kind = "signal"
        c.methods.append(m)
    for i in range(ccount):
        c.ctors.append(method(i, coff, True))
    notify_base = poff + pw * pcount
    has_notify_array = major == 5
    for i in range(pcount):
        p = poff + i * pw
        flags = at(p + 2)
        notify: int | None = None
        if major == 6:       # Qt6 has no Notify flag: ``notifyId`` is -1 or the signal index
            nid = at(p + 3)
            notify = nid if nid != 0xFFFFFFFF and nid < max(h[13], 1) else None
        elif has_notify_array and (flags & PROP_NOTIFY):
            nid = at(notify_base + i)
            notify = nid if nid != 0xFFFFFFFF else None
        c.props.append(QtProp(i, strings.get(at(p)) or "?", _type_name(strings, at(p + 1)), flags, notify))
    for i in range(ecount):
        p = eoff + i * ew
        ename = strings.get(at(p)) or "?"
        flags = at(p + (2 if ew == 5 else 1))
        count = at(p + (3 if ew == 5 else 2))
        data = at(p + (4 if ew == 5 else 3))
        vals: list[tuple[str, int]] = []
        for k in range(min(count, 4096)):
            vals.append((strings.get(at(data + 2 * k)) or "?", at(data + 2 * k + 1)))
        c.enums.append(QtEnum(i, ename, bool(flags & 1), vals))
    return c


def _getter_target(img: Image, fn: int, depth: int = 3) -> tuple[str, int] | None:
    """What the ``SuperData`` getter returns: ``("addr", a)`` for ``lea rax,[rip+d]; ret`` (a metaobject of
    this image), ``("slot", a)`` for ``mov rax,[rip+d]; ret`` (the import slot of the parent's
    ``staticMetaObject``). 32-bit forms ``mov eax,imm`` / ``mov eax,[imm]`` too; ``jmp`` thunks are followed."""
    b = img.read(fn, 8)
    if b is None or depth < 0:
        return None
    mask = 2 ** (8 * img.psize) - 1
    if img.psize == 8 and b[0] == 0x48 and b[2] == 0x05 and b[7] == 0xC3 and b[1] in (0x8D, 0x8B):
        a = (fn + 7 + struct.unpack_from("<i", b, 3)[0]) & mask
        return ("addr" if b[1] == 0x8D else "slot", a)
    if img.psize == 4 and b[0] in (0xB8, 0xA1) and b[5] == 0xC3:
        return ("addr" if b[0] == 0xB8 else "slot", struct.unpack_from("<I", b, 1)[0])
    if b[0] == 0xE9:
        return _getter_target(img, (fn + 5 + struct.unpack_from("<i", b, 1)[0]) & mask, depth - 1)
    return None


_MSVC_META = re.compile(r"\?staticMetaObject@((?:[A-Za-z_]\w*@)+)@")


def parent_from_import(name: str) -> str:
    """Class name out of the import name of ``staticMetaObject`` (MSVC ``?staticMetaObject@B@A@@2U...``)."""
    m = _MSVC_META.search(name)
    if m:
        return "::".join(reversed([p for p in m.group(1).split("@") if p]))
    m = re.search(r"([A-Za-z_][\w:]*)::staticMetaObject\b", name)
    return m.group(1) if m else ""


def parse_image(img: Image, imports: dict[int, str] | None = None) -> list[QtClass]:
    """Every QMetaObject of the image, with the parent class name where the file holds a pointer to
    another metaobject of the image (or, with ``imports`` = {import slot address: name}, a getter that loads the
    parent's import). Sorted by name.

    Qt6 built with ``QT_NO_DATA_RELOCATION`` (Windows) has a two word ``SuperData`` ``{direct, getter}``: the scan
    finds the getter word, ``QMetaObject`` starts one pointer earlier, and the parent comes from the getter."""
    classes: list[QtClass] = []
    seen: set[int] = set()
    cands = _candidates(img)
    ps = img.psize
    indirect = any(c[1] and c[6] is not None and img.is_code(c[1]) for c in cands)
    for cand in cands:
        if cand[0] in seen:
            continue
        try:
            c = _decode(img, cand)
        except (struct.error, IndexError, ValueError):
            c = None
        if c is None or not c.name:
            continue
        if indirect and c.major == 6:
            getter, c.super_addr = c.super_addr, None
            c.meta -= ps
            direct = img.ptr(c.meta)
            if getter and img.is_code(getter):
                t = _getter_target(img, getter)
                if t is not None and t[0] == "addr":
                    c.super_addr = t[1]
                elif t is not None and imports:
                    c.parent = parent_from_import(imports.get(t[1], ""))
            elif direct and img.in_image(direct):
                c.super_addr = direct
        if c.meta in seen:
            continue
        seen.add(c.meta)
        classes.append(c)
    by_meta = {c.meta: c for c in classes}
    for c in classes:
        if c.super_addr and c.super_addr in by_meta and not c.parent:
            c.parent = by_meta[c.super_addr].name
    classes.sort(key=lambda c: (c.name, c.meta))
    return classes


# ── storage ────────────────────────────────────────────────────────────────

SCHEMA_TABLES = ("qt_class", "qt_method", "qt_prop", "qt_enum", "qt_connect")


def clear_binary(store: Store, binary_id: int) -> None:
    for t in SCHEMA_TABLES:
        store.db.execute(f"DELETE FROM {t} WHERE binary_id=?", (binary_id,))


def store_rows(store: Store, binary_id: int, classes: list[QtClass]) -> None:
    db = store.db
    with db:
        clear_binary(store, binary_id)
        db.executemany(
            "INSERT OR REPLACE INTO qt_class(binary_id, meta_addr, name, major, revision, super_addr, parent, "
            "metacall, data_addr, nsignals, nmethods, nprops, nenums, nctors, info) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(binary_id, c.meta, c.name, c.major, c.revision, c.super_addr, c.parent, c.metacall, c.data_addr,
              c.nsignals, len(c.methods), len(c.props), len(c.enums), len(c.ctors),
              ";".join(f"{k}={v}" for k, v in c.info)) for c in classes])
        rows = []
        for c in classes:
            for m in c.methods + c.ctors:
                rows.append((binary_id, c.meta, m.idx, m.kind, m.name, m.ret,
                             ", ".join(f"{t} {n}".strip() for t, n in m.params), m.access, m.flags))
        db.executemany("INSERT OR REPLACE INTO qt_method(binary_id, meta_addr, idx, kind, name, ret, params, "
                       "access, flags) VALUES (?,?,?,?,?,?,?,?,?)", rows)
        db.executemany("INSERT OR REPLACE INTO qt_prop(binary_id, meta_addr, idx, name, type, flags, notify) "
                       "VALUES (?,?,?,?,?,?,?)",
                       [(binary_id, c.meta, p.idx, p.name, p.type, p.flags, p.notify)
                        for c in classes for p in c.props])
        db.executemany("INSERT OR REPLACE INTO qt_enum(binary_id, meta_addr, idx, name, is_flag, vals) "
                       "VALUES (?,?,?,?,?,?)",
                       [(binary_id, c.meta, e.idx, e.name, int(e.is_flag),
                         ",".join(f"{n}={v}" for n, v in e.values)) for c in classes for e in c.enums])
        store.set_meta(meta_key(binary_id), str(QT_VERSION))
        store.db.execute("DELETE FROM meta WHERE key=?", (dispatch_key(binary_id),))


def pe_import_rows(path: Path) -> list[tuple[str, str, int]]:
    """(dll, symbol name, import slot address) of the by-name imports of a PE (empty on any problem)."""
    out: list[tuple[str, str, int]] = []
    try:
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = d.dll.decode("latin-1").upper() if d.dll else ""
                for imp in d.imports:
                    if imp.name and imp.address:
                        out.append((dll, imp.name.decode("latin-1"), int(imp.address)))
        finally:
            pe.close()
    except Exception:  # noqa: BLE001  an extra: parents from imports are then left to the worker
        return out
    return out


def pe_imports(path: Path) -> dict[int, str]:
    """{import slot address: symbol name} of the by-name imports of a PE."""
    return {a: n for _d, n, a in pe_import_rows(path)}


_MSVC_FN = re.compile(r"^\?(\?[01])?((?:[A-Za-z_][\w]*@)+)@")


_ITANIUM_ID = re.compile(r"(\d+)")
_ITANIUM_CD = re.compile(r"^(C[1-3]|D[0-5])")


def _itanium_qualname(mangled: str) -> str:
    """``_ZN7QObject11connectImplEPKS_...`` -> ``QObject::connectImpl`` (nested names of plain identifiers,
    constructors and destructors; "" for templates, substitutions and operators)."""
    i = 4 if mangled.startswith("_ZNK") else 3
    parts: list[str] = []
    while i < len(mangled):
        m = _ITANIUM_ID.match(mangled, i)
        if not m:
            break
        n = int(m.group(1))
        ident = mangled[m.end():m.end() + n]
        if len(ident) != n:
            return ""
        parts.append(ident)
        i = m.end() + n
    if not parts:
        return ""
    cd = _ITANIUM_CD.match(mangled[i:i + 2]) if i < len(mangled) else None
    if cd:
        name = ("~" if cd.group(1)[0] == "D" else "") + parts[-1]
        return "::".join([*parts, name])
    if mangled[i:i + 1] != "E":      # template arguments (I...), operators, substitutions: not read
        return ""
    return "::".join(parts)


def import_qualname(mangled: str) -> str:
    """``?connectImpl@QObject@@CA...`` / ``_ZN7QObject11connectImplE...`` -> ``QObject::connectImpl``;
    ``??0Foo@@...`` -> ``Foo::Foo``; "" for the forms this does not read (templates, operators)."""
    if mangled.startswith("_ZN"):
        return _itanium_qualname(mangled)
    m = _MSVC_FN.match(mangled)
    if not m:
        return ""
    parts = [p for p in m.group(2).split("@") if p]
    if m.group(1):                      # constructor / destructor: the first part is the class
        name, scopes = ("~" if m.group(1) == "?1" else "") + parts[0], parts
    else:
        name, scopes = parts[0], parts[1:]
    return "::".join([*reversed(scopes), name])


def fill_imports(store: Store, binary_id: int, artifact: Path) -> int:
    """Add the C++ imports (mangled names) the analysis left out of the ``import`` table: Ghidra files them under
    the class namespace of the external library, so neither the import row nor a call edge to a function
    exists, only a read edge to the import slot. Rows are named ``Class::method``. Returns rows added."""
    rows = pe_import_rows(artifact)
    have = {r[0] for r in store.db.execute("SELECT address FROM import WHERE binary_id=? AND address IS NOT NULL",
                                           (binary_id,))}
    add = []
    for dll, name, slot in rows:
        if slot in have or not name.startswith(("?", "_ZN")):
            continue
        q = import_qualname(name)
        if q:
            add.append((binary_id, dll, q, None, slot, None))
    if add:
        with store.db:
            store.db.executemany("INSERT INTO import(binary_id, dll, name, ordinal, address, resolved) "
                                 "VALUES (?,?,?,?,?,?)", add)
    return len(add)


def parse_file(path: Path) -> list[QtClass] | None:
    img = Image.from_pe(path)
    return None if img is None else parse_image(img, pe_imports(path))


def derive_binary(store: Store, binary_id: int, artifact: Path) -> tuple[int, int, int]:
    """Parse ``artifact`` and replace the Qt rows of the binary. Returns (classes, signals, slots)."""
    classes = parse_file(artifact) or []
    store_rows(store, binary_id, classes)
    sig = sum(1 for c in classes for m in c.methods if m.kind == "signal")
    slt = sum(1 for c in classes for m in c.methods if m.kind == "slot")
    return len(classes), sig, slt


_QT_DLL = re.compile(r"^qt\d*\w*\.dll$", re.I)


def is_qt(b: Binary) -> bool:
    """Binaries worth scanning: built against Qt (toolchain ``qt``) or a Qt library itself."""
    return b.toolchain == "qt" or bool(_QT_DLL.match(b.name or ""))


def stale(store: Store, binary_id: int) -> bool:
    return store.get_meta(meta_key(binary_id)) != str(QT_VERSION)


def ensure(store: Store, binary: Binary, artifact: Path) -> bool:
    """Derive the Qt rows of a Qt binary when missing or from an older QT_VERSION. Never raises;
    True when rows were (re)written."""
    if not is_qt(binary) or not stale(store, binary.id) or not artifact.is_file():
        return False
    try:
        derive_binary(store, binary.id, artifact)
        fill_imports(store, binary.id, artifact)
        derive_connects(store, binary.id)
        return True
    except Exception as e:  # noqa: BLE001  an extra; the binary stays usable
        log.warning("Qt analysis of %s failed: %s", binary.name, e)
        return False


def ensure_project(store: Store, artifacts: Path) -> int:
    n = 0
    for b in store.list_binaries():
        if store.get_meta(f"status:{b.id}") == "ready" and ensure(store, b, artifacts / b.sha256):
            n += 1
    return n


# ── worker results ─────────────────────────────────────────────────────────

def dispatch_pending(store: Store, binary_id: int) -> list[dict]:
    """Classes the worker op ``qt_dispatch`` should look at: metacall address, method indices, and the
    metaobject address when the parent is unknown."""
    if store.get_meta(dispatch_key(binary_id)) == str(DISPATCH_VERSION):
        return []
    out = []
    for r in store.db.execute(
            "SELECT meta_addr, name, metacall, super_addr, parent FROM qt_class WHERE binary_id=?", (binary_id,)):
        out.append({"meta": r["meta_addr"], "name": r["name"], "metacall": r["metacall"],
                    "need_parent": not r["parent"]})
    return out


def store_dispatch(store: Store, binary_id: int, result: dict) -> tuple[int, int]:
    """Write the worker result: ``classes`` is a list of {meta, cases: {idx: addr}, parent}. Returns
    (methods mapped, parents found)."""
    mapped = parents = 0
    with store.db:
        for c in result.get("classes", []):
            meta = int(c["meta"])
            for idx, addr in (c.get("cases") or {}).items():
                cur = store.db.execute(
                    "UPDATE qt_method SET addr=? WHERE binary_id=? AND meta_addr=? AND idx=? "
                    "AND kind<>'constructor'", (int(addr), binary_id, meta, int(idx)))
                mapped += cur.rowcount
            if c.get("parent"):
                store.db.execute("UPDATE qt_class SET parent=? WHERE binary_id=? AND meta_addr=? AND parent=''",
                                 (c["parent"], binary_id, meta))
                parents += 1
        store.set_meta(dispatch_key(binary_id), str(DISPATCH_VERSION))
    return mapped, parents


def resolve(ix: Any, project: str, store: Store, b: Binary) -> tuple[int, int]:
    """Run the worker op ``qt_dispatch`` for one ready Qt binary (once per DISPATCH_VERSION): creates the
    dispatcher functions Ghidra missed, then stores method addresses and imported parents. Returns
    (methods mapped, parents found); never raises for a worker that does not know the op."""
    program = store.get_meta(f"program:{b.id}")
    if not program or not is_qt(b) or stale(store, b.id):
        return 0, 0
    pend = dispatch_pending(store, b.id)
    if not pend:
        return 0, 0
    ix.ensure_open(project)
    nm = {r[0]: r[1] for r in store.db.execute(
        "SELECT meta_addr, nmethods FROM qt_class WHERE binary_id=?", (b.id,))}
    for p in pend:
        p["nmethods"] = nm.get(p["meta"], 0)
    mcs = sorted({p["metacall"] for p in pend if p["metacall"]
                  and not store.db.execute("SELECT 1 FROM function WHERE binary_id=? AND space='ram' AND entry=?",
                                           (b.id, p["metacall"])).fetchone()})
    if mcs:
        r = ix.worker.request("create_functions", {"program": program, "addresses": mcs}, timeout=3600)
        if r.get("created"):
            ix.reextract_code(store, b, program)
    res = ix.worker.request("qt_dispatch", {"program": program, "classes": pend}, timeout=3600)
    out = store_dispatch(store, b.id, res)
    sites = [dict(r) for r in store.db.execute(
        "SELECT fn_entry AS fn, site FROM qt_connect WHERE binary_id=? AND kind='ptr' AND signal='' ORDER BY site",
        (b.id,))]
    if sites:        # pointer-to-member connects: the signal and the slot of each connectImpl call site
        try:
            imps = {r[0]: r[1] for r in store.db.execute(
                "SELECT address, name FROM import WHERE binary_id=? AND address IS NOT NULL AND name LIKE '%::%'",
                (b.id,))}
            cres = ix.worker.request("qt_connects", {"program": program, "sites": sites, "imports": imps},
                                     timeout=3600)
            store_connects(store, b.id, cres, sites)
            if (cres.get("stats") or {}).get("signatures", 0) > 0:
                bump_connect_callers(store, b.id)      # the signature changed the decompiler output of the callers
        except Exception as e:  # noqa: BLE001  an extra: the call sites stay listed
            log.warning("Qt pointer connects of %s failed: %s", b.name, e)
    return out


def bump_connect_callers(store: Store, binary_id: int) -> int:
    """Invalidate the cached decompiles of every function that calls ``connectImpl`` (its signature changed, so
    the decompiler output differs): ``function.version`` +1 through ``Store.bump_versions``. Returns rows bumped."""
    slots = [a for a, k in _connect_slots(store.db, binary_id).items() if k == "ptr"]
    ids = {r[0] for r in store.db.execute("SELECT DISTINCT src_fn FROM edge WHERE binary_id=? AND src_fn IS NOT NULL "
                                          "AND dst_addr IN (%s)" % ",".join("?" * len(slots)), (binary_id, *slots))}         if slots else set()
    ids |= {r[0] for r in store.db.execute(
        "SELECT f.id FROM qt_connect q JOIN function f ON f.binary_id=q.binary_id AND f.entry=q.fn_entry "
        "WHERE q.binary_id=? AND q.kind='ptr'", (binary_id,))}
    cfn = [i for i, k in _connect_functions(store.db, binary_id).items() if k == "ptr"]
    if cfn:
        ids |= {r[0] for r in store.db.execute("SELECT DISTINCT src_fn FROM edge WHERE binary_id=? AND src_fn IS NOT NULL "
                                               "AND dst_fn IN (%s)" % ",".join("?" * len(cfn)), (binary_id, *cfn))}
    return store.bump_versions(ids)


def store_connects(store: Store, binary_id: int, result: dict, sites: list[dict]) -> tuple[int, int]:
    """Write the worker result of ``qt_connects``: one ``ptr`` row per resolved connection (filed at the call that
    holds the member pointers, which can be a caller of the function with the ``connectImpl`` call), the sites
    without a result stay as empty rows. ``signal`` is ``Class::name(args)`` (a signal of the binary, by
    metaobject and index, or by function address) or ``Class::name`` (an imported signal); ``slot`` is the
    function address ``0x...`` (``slot_kind`` slot, signal, fn, functor) or an imported function name (ext).
    Returns (connections resolved, sites unresolved)."""
    db = store.db
    sig_by_idx: dict[tuple[int, int], str] = {}
    by_addr: dict[int, tuple[str, str]] = {}
    for r in db.execute("SELECT m.meta_addr, m.idx, m.kind, m.name, m.params, m.addr, c.name AS cname FROM qt_method m "
                        "JOIN qt_class c ON c.binary_id=m.binary_id AND c.meta_addr=m.meta_addr "
                        "WHERE m.binary_id=? AND m.kind<>'constructor'", (binary_id,)):
        types = ",".join(p.rsplit(" ", 1)[0] if " " in p.strip() else p for p in r["params"].split(", ") if p)
        text = f"{r['cname']}::{r['name']}({types})"
        sig_by_idx[(r["meta_addr"], r["idx"])] = text
        if r["addr"] is not None:
            by_addr.setdefault(r["addr"], (text, r["kind"]))
    rows = []
    found = set()
    for r in result.get("results", []):
        sg, sl = r.get("signal") or {}, r.get("slot") or {}
        if sg.get("ext"):
            sig = sg["ext"]
        elif sg.get("virtual") is not None:
            sig = f"vtable+0x{sg['virtual']:x}"
        elif "meta" in sg and (sg["meta"], sg.get("idx", -1)) in sig_by_idx:
            sig = sig_by_idx[(sg["meta"], sg["idx"])]
        elif sg.get("addr") in by_addr:
            sig = by_addr[sg["addr"]][0]
        else:
            sig = f"0x{sg.get('addr', 0):x}"
        if sl.get("ext"):
            slot, kind = sl["ext"], "ext"
        elif sl.get("virtual") is not None:
            slot, kind = f"vtable+0x{sl['virtual']:x}", "virtual"
        elif sl.get("addr") is None:
            slot, kind = "", ""
        else:
            slot = f"0x{sl['addr']:x}"
            kind = "functor" if sl.get("kind") == "functor" else (by_addr.get(sl["addr"], ("", "fn"))[1])
            if kind == "method":
                kind = "slot"
        rows.append((binary_id, r["fn"], r["site"], "ptr", sig, slot, kind))
        found.add(r.get("origin", r["site"]))        # a call chased up to a caller counts for the site it started at
    expanded = {int(k): v for k, v in (result.get("expanded") or {}).items()}
    if expanded:        # a site that is no call (the import was loaded into a register) stands for the calls of its function
        sites = [x for s in sites for x in ([{"fn": s["fn"], "site": c} for c in expanded[s["site"]]]
                                            if s["site"] in expanded else [s])]
        sites = list({(s["fn"], s["site"]): s for s in sites}.values())
    left = [s for s in sites if s["site"] not in found]
    rows += [(binary_id, s["fn"], s["site"], "ptr", "", "", "") for s in left]
    with db:
        db.execute("DELETE FROM qt_connect WHERE binary_id=? AND kind='ptr'", (binary_id,))
        db.executemany("INSERT INTO qt_connect(binary_id, fn_entry, site, kind, signal, slot, slot_kind) "
                       "VALUES (?,?,?,?,?,?,?)", rows)
    return len(rows) - len(left), len(left)


def resolve_project(ix: Any, project: str, store: Store) -> int:
    """``resolve`` for the ready Qt binaries that are not done (old projects: no re-analysis)."""
    n = 0
    for b in store.list_binaries():
        if not is_qt(b) or ix.get_status(store, b.id)[0] != "ready" or ix.job_for(project, b.id) is not None:
            continue
        try:
            n += resolve(ix, project, store, b)[0]
        except Exception as e:  # noqa: BLE001  one binary must not stop the others
            log.warning("Qt dispatch of %s failed: %s", b.name, e)
    return n


# ── string-based connections ───────────────────────────────────────────────

_SIGSLOT = re.compile(r"^([12])\s*([A-Za-z_]\w*)\((.*)\)$")


_NORM_TYPE = re.compile(r"\bconst\b|[&\s]")


def _norm_args(args: str) -> str:
    """``QString const &, int`` -> ``QString,int`` (what the metaobject stores)."""
    return ",".join(_NORM_TYPE.sub("", a) for a in args.split(",")) if args.strip() else ""


_CONNECT_NAME = re.compile(r"^(?:connect|connectImpl)$|^\?connect(?:Impl)?@QObject@@")


def _connect_functions(db, binary_id: int) -> dict[int, str]:
    """{function id: 'string' | 'ptr'} for QObject::connect (const char * form) and connectImpl (pointer to
    member form): external rows, thunks and demangled or mangled names, in any binary of the store (the
    Qt DLL may be a project binary or an external library)."""
    out: dict[int, str] = {}
    for r in db.execute("SELECT id, name, namespace FROM function WHERE binary_id=? AND (name LIKE '%onnect%')",
                        (binary_id,)):
        name, ns = r["name"], r["namespace"] or ""
        if not _CONNECT_NAME.match(name):
            continue
        if not (ns.endswith("QObject") or name.startswith("?")):
            continue
        out[r["id"]] = "ptr" if "Impl" in name else "string"
    return out


_CONNECT_IMPORT = re.compile(r"(?:^|::)QObject::connect(Impl)?$")


def _connect_slots(db, binary_id: int) -> dict[int, str]:
    """{import slot address: 'string' | 'ptr'} of the imported ``QObject::connect`` / ``connectImpl``: the
    import row (a call through the slot is only a read edge to the slot, there is no edge to a function)."""
    out: dict[int, str] = {}
    for r in db.execute("SELECT name, address FROM import WHERE binary_id=? AND address IS NOT NULL "
                        "AND name LIKE '%onnect%'", (binary_id,)):
        m = _CONNECT_IMPORT.search(r["name"] or "")
        if m:
            out[r["address"]] = "ptr" if m.group(1) else "string"
    return out


def derive_connects(store: Store, binary_id: int) -> int:
    """Connections of a Qt binary, from the string and edge tables.

    * ``connect(sender, SIGNAL(a()), receiver, SLOT(b()))`` (Qt4 style): each call of ``QObject::connect`` takes
      the ``2name(args)`` / ``1name(args)`` strings referenced since the previous connect call of the function
      (the two closest to the call). The signal is the string that starts with ``2``; if both do, the order of
      the argument pushes decides (32-bit cdecl pushes the slot first).
    * ``connectImpl`` (pointer to member form) takes no strings: each call site is listed (kind ``ptr``).
    * Pairs made by order alone (strings no call site claimed, or no connect function at all) are a guess: kind
      ``string-guess``, not counted as connections.
    * Without any identifiable connect function (a statically linked Qt), a signal string is paired with the
      next string of the same function.
    """
    q = store.db
    b = store.get_binary_by_id(binary_id)
    psize = (b.pointer_size if b else 4) or 4
    strs = q.execute(
        "SELECT s.value, e.src_addr, f.entry FROM string s "
        "JOIN edge e ON e.binary_id=s.binary_id AND e.dst_addr=s.address AND e.kind IN ('read','data','param') "
        "JOIN function f ON f.id=e.src_fn "
        "WHERE s.binary_id=? AND s.encoding<>'utf16' AND (s.value LIKE '1%(%)' OR s.value LIKE '2%(%)') "
        "AND length(s.value)<200 ORDER BY f.entry, e.src_addr", (binary_id,)).fetchall()
    by_fn: dict[int, list[tuple[int, str, int]]] = {}
    for r in strs:
        m = _SIGSLOT.match(r["value"])
        if m:
            by_fn.setdefault(r["entry"], []).append((r["src_addr"], r["value"], int(m.group(1))))
    cfn = _connect_functions(q, binary_id)
    calls: dict[int, list[tuple[int, str]]] = {}
    if cfn:
        marks = ",".join("?" * len(cfn))
        for r in q.execute(
                f"SELECT e.src_addr, f.entry, e.dst_fn FROM edge e JOIN function f ON f.id=e.src_fn "
                f"WHERE e.binary_id=? AND e.dst_fn IN ({marks}) ORDER BY f.entry, e.src_addr",
                (binary_id, *cfn)):
            calls.setdefault(r["entry"], []).append((r["src_addr"], cfn[r["dst_fn"]]))
    slots = _connect_slots(q, binary_id)
    if slots:
        marks = ",".join("?" * len(slots))
        for r in q.execute(
                f"SELECT e.src_addr, f.entry, e.dst_addr FROM edge e JOIN function f ON f.id=e.src_fn "
                f"WHERE e.binary_id=? AND e.dst_addr IN ({marks}) AND e.kind IN ('read','call_imp','call','data') "
                f"ORDER BY f.entry, e.src_addr", (binary_id, *slots)):
            calls.setdefault(r["entry"], []).append((r["src_addr"], slots[r["dst_addr"]]))
    for cl in calls.values():
        cl.sort()

    def pair(a: tuple[int, str, int], bb: tuple[int, str, int]) -> tuple | None:
        sa, sb = _SIGSLOT.match(a[1]), _SIGSLOT.match(bb[1])
        if a[2] == 2 and bb[2] == 1:
            sig, slt = (a, sa), (bb, sb)
        elif a[2] == 1 and bb[2] == 2:
            sig, slt = (bb, sb), (a, sa)
        elif a[2] == 2 and bb[2] == 2:
            sig, slt = ((a, sa), (bb, sb)) if psize == 8 else ((bb, sb), (a, sa))
        else:
            return None
        return (f"{sig[1].group(2)}({_norm_args(sig[1].group(3))})", f"{slt[1].group(2)}({_norm_args(slt[1].group(3))})",
                "slot" if slt[0][2] == 1 else "signal", min(a[0], bb[0]))

    out: list[tuple] = []
    seen_fn: set[int] = set()
    for fn, cl in calls.items():
        seen_fn.add(fn)
        refs = by_fn.get(fn, [])
        prev = -1
        used: set[int] = set()
        has_string = False
        for site, kind in cl:
            if kind == "ptr":
                out.append((binary_id, fn, site, "ptr", "", "", ""))
                prev = site
                continue
            has_string = True
            window = [r for r in refs if prev < r[0] < site]
            prev = site
            if len(window) >= 2:
                got = pair(window[-2], window[-1])
                if got is not None:
                    out.append((binary_id, fn, site, "string", got[0], got[1], got[2]))
                    used.update((window[-2][0], window[-1][0]))
        if has_string:
            # the compiler may load the import into a register once and call it from there (MinGW): the strings
            # that no call site claimed are paired in order, as without any connect function
            rest = [r for r in refs if r[0] not in used]
            i = 0
            while i + 1 < len(rest):
                got = pair(rest[i], rest[i + 1])
                if got is not None:
                    out.append((binary_id, fn, got[3], "string-guess", got[0], got[1], got[2]))
                    i += 2
                else:
                    i += 1
    if not calls:
        for fn, refs in by_fn.items():
            i = 0
            while i + 1 < len(refs):
                got = pair(refs[i], refs[i + 1])
                if got is not None:
                    out.append((binary_id, fn, got[3], "string-guess", got[0], got[1], got[2]))
                    i += 2
                else:
                    i += 1
    with q:
        q.execute("DELETE FROM qt_connect WHERE binary_id=?", (binary_id,))
        q.executemany("INSERT INTO qt_connect(binary_id, fn_entry, site, kind, signal, slot, slot_kind) "
                      "VALUES (?,?,?,?,?,?,?)", out)
    return sum(1 for o in out if o[3] == "string")


# ── hints, map line, runtime recognition ───────────────────────────────────

def hints_for(store: Store, binary_id: int, entry: int) -> list[str]:
    """Hints for a function entry: ``Class::name (Qt slot) of Class(int, QString)``, the moc dispatcher
    ``Class::qt_static_metacall`` and the moc virtuals ``Class::metaObject`` / ``qt_metacast`` / ``qt_metacall``."""
    out: list[str] = []
    q = store.db.execute
    try:
        for r in q("SELECT c.name, m.kind, m.name, m.params FROM qt_method m JOIN qt_class c "
                   "ON c.binary_id=m.binary_id AND c.meta_addr=m.meta_addr WHERE m.binary_id=? AND m.addr=? "
                   "ORDER BY c.meta_addr LIMIT 3", (binary_id, entry)):
            out.append(f"{r[0]}::{r[2]}({r[3]}) (Qt {r[1]})")
        for r in q("SELECT name FROM qt_class WHERE binary_id=? AND metacall=? LIMIT 2", (binary_id, entry)):
            out.append(f"{r[0]}::qt_static_metacall (moc dispatcher)")
        names = ("metaObject", "qt_metacast", "qt_metacall")
        for r in q("SELECT c.name, s.slot FROM vtable_slot s JOIN rtti_class t ON t.binary_id=s.binary_id AND "
                   "t.vtable_addr=s.vtable_addr JOIN qt_class c ON c.binary_id=t.binary_id AND c.name=t.name "
                   "WHERE s.binary_id=? AND s.target=? AND s.slot<3 ORDER BY s.slot LIMIT 3", (binary_id, entry)):
            out.append(f"{r[0]}::{names[r[1]]} (moc generated)")
    except Exception:  # noqa: BLE001  an extra
        return out
    return out


def ui_line(store: Store, binary_id: int) -> str:
    """One line for the project map: ``Qt: 40 classes, 31 signals, 120 slots (110 mapped to functions)``;
    empty for a binary without metaobjects."""
    try:
        n = store.db.execute("SELECT COUNT(*) FROM qt_class WHERE binary_id=?", (binary_id,)).fetchone()[0]
        if not n:
            return ""
        r = store.db.execute(
            "SELECT SUM(kind='signal'), SUM(kind='slot'), SUM(kind IN ('signal','slot') AND addr IS NOT NULL) "
            "FROM qt_method WHERE binary_id=?", (binary_id,)).fetchone()
        c = store.db.execute("SELECT COUNT(*) FROM qt_connect WHERE binary_id=? AND kind='string'", (binary_id,)).fetchone()[0]
        g = store.db.execute("SELECT COUNT(*) FROM qt_connect WHERE binary_id=? AND kind='string-guess'",
                             (binary_id,)).fetchone()[0]
        pc = store.db.execute("SELECT COUNT(*), SUM(signal<>'') FROM qt_connect WHERE binary_id=? AND kind='ptr'",
                              (binary_id,)).fetchone()
    except Exception:  # noqa: BLE001  an extra
        return ""
    extra = f", string connections {c}" if c else ""
    if g:
        extra += f", {g} string pairs guessed by order"
    if pc and pc[0]:
        extra += f", pointer connects {pc[1] or 0} of {pc[0]} call sites resolved"
    return f"Qt: {n} classes, signals {r[0] or 0}, slots {r[1] or 0} ({r[2] or 0} signals and slots mapped to functions){extra}"


def runtime_addrs(store: Store, binary_id: int) -> set[int]:
    """Functions that are moc boilerplate: the dispatcher and the three moc virtuals of every Qt class."""
    out: set[int] = set()
    try:
        out.update(r[0] for r in store.db.execute(
            "SELECT metacall FROM qt_class WHERE binary_id=? AND metacall IS NOT NULL", (binary_id,)))
        out.update(r[0] for r in store.db.execute(
            "SELECT s.target FROM vtable_slot s JOIN rtti_class t ON t.binary_id=s.binary_id AND "
            "t.vtable_addr=s.vtable_addr JOIN qt_class c ON c.binary_id=t.binary_id AND c.name=t.name "
            "WHERE s.binary_id=? AND s.slot<3", (binary_id,)))
    except Exception:  # noqa: BLE001  an extra
        pass
    return out


# ── feature seeds ──────────────────────────────────────────────────────────

# sender class -> signals whose slots are user interface handlers (feature key). A subclass is covered through
# the parent chain (``qt_class.parent`` for classes of the binary, ``_QT_BASES`` for the Qt library ones).
_SEED_SIGNALS: dict[str, tuple[str, frozenset[str]]] = {
    "QAction": ("ui-menu", frozenset({"triggered", "toggled"})),
    "QActionGroup": ("ui-menu", frozenset({"triggered"})),
    "QMenu": ("ui-menu", frozenset({"triggered", "aboutToShow"})),
    "QMenuBar": ("ui-menu", frozenset({"triggered"})),
    "QAbstractButton": ("ui-dialog", frozenset({"clicked", "toggled", "pressed", "released"})),
    "QDialog": ("ui-dialog", frozenset({"accepted", "rejected", "finished"})),
    "QDialogButtonBox": ("ui-dialog", frozenset({"accepted", "rejected", "clicked"})),
    "QWizard": ("ui-dialog", frozenset({"accepted", "rejected", "finished", "currentIdChanged"})),
}
_QT_BASES = {
    **{c: "QAbstractButton" for c in ("QPushButton", "QToolButton", "QCheckBox", "QRadioButton", "QCommandLinkButton")},
    **{c: "QDialog" for c in ("QMessageBox", "QFileDialog", "QInputDialog", "QProgressDialog", "QColorDialog",
                              "QFontDialog", "QErrorMessage", "QWizard")},
}
# a string connect names no class: these signal names are enough
_SEED_NAME_ONLY = {"triggered": "ui-menu", "clicked": "ui-dialog", "accepted": "ui-dialog", "rejected": "ui-dialog"}
_PTR_SIG = re.compile(r"^(?:(.+)::)?(\w+)(?:\(.*\))?$")


def seed_for_signal(cls: str, name: str, parents: dict[str, str]) -> tuple[str, str] | None:
    """(feature key, evidence) for a signal ``cls::name`` that fires a user interface handler, else None.
    ``parents`` maps a class of the binary to its parent."""
    seen = 0
    c = cls
    while c and seen < 16:
        hit = _SEED_SIGNALS.get(c)
        if hit and name in hit[1]:
            return hit[0], f"Qt {c}::{name}"
        c = parents.get(c) or _QT_BASES.get(c, "")
        seen += 1
    return None


def feature_seeds(store: Store, binary_id: int) -> list[tuple[int, str, str]]:
    """(function address, feature key, evidence) for the handlers connected to user interface signals:
    pointer connects (class and signal known, slot address in ``qt_connect.slot``) and string connects
    (signal name only; the slot must name one function in the binary)."""
    db = store.db
    out: list[tuple[int, str, str]] = []
    try:
        parents = {r[0]: r[1] for r in db.execute(
            "SELECT name, parent FROM qt_class WHERE binary_id=? AND parent<>''", (binary_id,))}
        by_sig: dict[str, set[int]] = {}
        for r in db.execute("SELECT name, params, addr FROM qt_method WHERE binary_id=? AND addr IS NOT NULL "
                            "AND kind IN ('slot','method')", (binary_id,)):
            types = ",".join(p.rsplit(" ", 1)[0] if " " in p.strip() else p for p in r["params"].split(", ") if p)
            by_sig.setdefault(f"{r['name']}({_norm_args(types)})", set()).add(r["addr"])
        for r in db.execute("SELECT kind, signal, slot FROM qt_connect WHERE binary_id=?", (binary_id,)):
            if r["kind"] == "ptr":
                m = _PTR_SIG.match(r["signal"] or "")
                try:
                    addr = int(r["slot"], 16) if (r["slot"] or "").startswith("0x") else None
                except ValueError:
                    addr = None
                got = seed_for_signal(m.group(1) or "", m.group(2), parents) if m else None
                if got and addr is not None:
                    out.append((addr, got[0], got[1]))
            elif r["kind"] == "string":
                m = _SIGSLOT.match("2" + (r["signal"] or ""))
                key = _SEED_NAME_ONLY.get(m.group(2)) if m else None
                s = _SIGSLOT.match("1" + (r["slot"] or ""))
                if key and s:
                    cand = by_sig.get(f"{s.group(2)}({_norm_args(s.group(3))})", set())
                    if len(cand) == 1:
                        out.append((next(iter(cand)), key, f"Qt connect {m.group(2)}"))
    except Exception:  # noqa: BLE001  an extra: the other seeds stay
        log.warning("Qt seeds of binary %s failed", binary_id)
    return out
