"""MFC beyond RTTI: runtime classes, names for classes without RTTI, dispatch / interface / event maps.

Pure PE bytes (``cpp.Image``), no worker and no Ghidra. Called by ``cpp.derive_binary``; the rows go to
``mfc_class`` and ``mfc_map_entry`` (schema v14, derived). Layouts (little endian, ``P`` = pointer size):

* ``CRuntimeClass`` (``DECLARE_DYNAMIC`` / ``DYNCREATE`` / ``SERIAL``): ``lpszClassName`` (P), ``nObjectSize``
  (u32), ``wSchema`` (u32: 0xFFFF, or the schema number, bit 31 = versionable), ``pfnCreateObject`` (P, code
  or 0), ``pBaseClass`` (P: the base's ``CRuntimeClass`` in static MFC, a ``GetBaseClass`` function in
  ``_AFXDLL``), ``pNextClass`` (P), ``pClassInit`` (P). 28 bytes in 32-bit, 48 in 64-bit.
* ``GetRuntimeClass`` is the first virtual function of ``CObject`` and returns ``&classX`` (a trivial getter),
  so a vtable starts at the slot whose getter returns a ``CRuntimeClass``; ``GetMessageMap``,
  ``GetDispatchMap``, ``GetInterfaceMap`` and ``GetEventSinkMap`` are further slots of the same vtable.
* ``AFX_DISPMAP``: ``pBaseMap | pfnGetBaseMap``, ``lpEntries``, ``lpEntryCount`` (a ``UINT`` that MFC fills
  at run time), ``lpStockPropMask``. ``AFX_DISPMAP_ENTRY``: ``lpszName`` (P), ``lDispID`` (i32), ``lpszParams``
  (P, ``VTS_*`` bytes), ``vt`` (u16), ``pfn`` (P), ``pfnSet`` (P), ``nPropOffset`` (P), ``flags`` (u32);
  natural alignment, 32 bytes in 32-bit and 64 in 64-bit; the table ends with ``lpszName`` NULL and
  ``nPropOffset`` -1.
* ``AFX_INTERFACEMAP``: base, ``pEntry``. Entry: ``piid`` (P, a GUID), ``nOffset`` (P); ends with NULL / -1.
* ``AFX_CONNECTIONMAP``: the same two pointers and the same entry (``piid`` of an outgoing interface,
  ``nOffset`` of the ``CConnectionPoint`` member). The shape cannot tell it from an interface map; the vtable
  can: ``GetConnectionMap`` is the slot right before ``GetInterfaceMap`` in every ``CCmdTarget`` vtable
  (``mark_connections``).
* ``AFX_EVENTSINKMAP``: base, ``lpEntries``, ``lpEntryCount``. Entry: an ``AFX_DISPMAP_ENTRY`` followed by
  ``nCtrlIDFirst`` and ``nCtrlIDLast`` (u32); ends like a dispatch map.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from airlock.server import cpp

NEAR = 0x4000                    # the vtable of a class is the closest one this near behind its CRuntimeClass
MAX_DISP = 4096
CALL_TO_STORE = 28              # bytes between the base constructor call and the vtable store
MAX_INTF = 64
KIND_DISPATCH, KIND_INTERFACE, KIND_EVENT, KIND_CONNECTION = "dispatch", "interface", "event", "connection"
EXTRA_KINDS = (KIND_DISPATCH, KIND_INTERFACE, KIND_EVENT, KIND_CONNECTION)
_IDENT = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]{1,79}$")
_DISP_NAME = re.compile(r"^(?:[A-Za-z_][\w$ .]{0,119})?$")


# ── CRuntimeClass ──────────────────────────────────────────────────────────

@dataclass
class RuntimeClass:
    addr: int
    name: str
    size: int
    schema: int
    create: int
    base: int                     # pBaseClass / pfnGetBaseClass as stored
    base_name: str = ""


def find_runtime_classes(img: cpp.Image) -> dict[int, RuntimeClass]:
    """Every plausible ``CRuntimeClass`` by address (the framework's own included)."""
    ps = img.psize
    fmt = "<IIIIIII" if ps == 4 else "<QIIQQQQ"
    sz = struct.calcsize(fmt)
    lo = min((s.va for s in img.sections), default=0)
    hi = max((s.end for s in img.sections), default=0)
    out: dict[int, RuntimeClass] = {}
    for s in img.sections:
        if s.executable or len(s.data) < sz:
            continue
        data = s.data
        view = memoryview(data)[:len(data) // ps * ps].cast("I" if ps == 4 else "Q")
        for i, w in enumerate(view):
            if w < lo or w >= hi or i * ps + sz > len(data):
                continue
            nm, size, schema, create, base, nxt, init = struct.unpack_from(fmt, data, i * ps)
            if not 4 <= size <= 0x1000000:
                continue
            if not (schema == 0xFFFF or 0 < (schema & 0x7FFFFFFF) < 0x1000):
                continue
            if create and not img.is_code(create):
                continue
            if nxt and not img.in_image(nxt):
                continue
            s2 = img.section_at(nm)
            if s2 is None or s2.executable:
                continue
            raw = img.cstr(nm, 90)
            if raw is None or not _IDENT.match(raw.encode("latin-1")):
                continue
            out[s.va + i * ps] = RuntimeClass(s.va + i * ps, raw, size, schema, create, base)
    for rc in list(out.values()):                      # base must be 0, another class, or a function
        b = rc.base
        if b == 0:
            continue
        if b in out:
            rc.base_name = out[b].name
        elif not img.is_code(b):
            del out[rc.addr]
    return out


# ── getters, vtable groups ─────────────────────────────────────────────────

class Getters:
    """Cached ``cpp.returned_address`` of functions."""

    def __init__(self, img: cpp.Image) -> None:
        self.img = img
        self._c: dict[int, int | None] = {}

    def of(self, fn: int) -> int | None:
        if fn not in self._c:
            self._c[fn] = cpp.returned_address(self.img, fn)
        return self._c[fn]


def code_runs(img: cpp.Image) -> Iterable[tuple[int, list[int]]]:
    """(address of the first slot, code pointers) for every run of code pointers in data sections."""
    ps = img.psize
    for va, words in img.data_words(ps):
        n = len(words)
        i = 0
        while i < n:
            v = words[i]
            if v and img.is_code(v):
                j = i
                while j < n and words[j] and img.is_code(words[j]):
                    j += 1
                yield va + i * ps, [words[k] for k in range(i, j)]
                i = j
            else:
                i += 1


@dataclass
class Group:
    """A vtable found through its ``GetRuntimeClass`` slot."""
    start: int
    rc: RuntimeClass
    fns: list[int]
    rtti: bool = False
    maps: dict[str, list[int]] = field(default_factory=dict)      # kind -> map addresses, slot order


def find_groups(img: cpp.Image, rcs: dict[int, RuntimeClass], gt: Getters, rtti_starts: set[int]) -> list[Group]:
    ps = img.psize
    out: list[Group] = []
    for start, fns in code_runs(img):
        cuts = [k for k, f in enumerate(fns) if gt.of(f) in rcs]
        for ci, k in enumerate(cuts):
            end = cuts[ci + 1] if ci + 1 < len(cuts) else len(fns)
            va = start + k * ps
            out.append(Group(va, rcs[gt.of(fns[k])], fns[k:end], va in rtti_starts))
    return out


def decide_owners(groups: list[Group]) -> dict[int, Group]:
    """CRuntimeClass address -> the group that owns it (the class that declares it). Groups that only
    inherit ``GetRuntimeClass`` of a base share the class and own nothing. The compiler emits the class
    object and its vtable together, so the owner is the closest vtable behind the ``CRuntimeClass``
    (within ``NEAR`` bytes; the dispatch and event tables of a control can sit in between). A binary that
    keeps them apart (fewer than half of the classes are adjacent) falls back to the only vtable of a class."""
    by_rc: dict[int, list[Group]] = {}
    for g in groups:
        by_rc.setdefault(g.rc.addr, []).append(g)
    first: dict[int, Group] = {}
    for rc, gs in by_rc.items():
        near = [g for g in gs if 0 <= g.start - rc <= NEAR]
        if near:
            first[rc] = min(near, key=lambda g: g.start - rc)
    adjacent = len(first) * 2 >= len(by_rc) if by_rc else False
    owners = dict(first)
    if not adjacent:
        owners.update({rc: gs[0] for rc, gs in by_rc.items() if len(gs) == 1})
    return owners


# ── dispatch, interface, event sink maps ───────────────────────────────────

@dataclass
class MapEntry:
    seq: int
    name: str
    id: int                       # dispid; interface: offset in the object; event: first control id
    vt: int
    flags: int
    pfn: int
    pfn_set: int
    extra: str                    # dispatch: params hex and data offset; interface: GUID; event: id range


@dataclass
class ExtraMap:
    cls: str
    kind: str
    addr: int
    entries: list[MapEntry]


def _fmt(ps: int) -> str:
    return "<IiIHxxIIII" if ps == 4 else "<QixxxxQHxxxxxxQQQIxxxx"


def _disp_entries(img: cpp.Image, ents: int, stride_extra: int) -> list[tuple] | None:
    """Raw dispatch entries at ``ents`` (each followed by ``stride_extra`` bytes), up to the terminator."""
    ps = img.psize
    fmt = _fmt(ps)
    size = struct.calcsize(fmt)
    allones = 2 ** (8 * ps) - 1
    out: list[tuple] = []
    for k in range(MAX_DISP):
        raw = img.read(ents + k * (size + stride_extra), size + stride_extra)
        if raw is None:
            return None
        name, did, params, vt, pfn, pfn_set, off, flags = struct.unpack_from(fmt, raw)
        if name == 0 and off == allones:
            return out if out else None
        if name:
            nm = disp_name(img, name)
            if nm is None or not _DISP_NAME.match(nm) or not img.is_data(name):
                return None
        elif not flags & 1 and not stride_extra:
            return None                                   # only stock properties have no name
        if params and not img.is_data(params):
            return None
        if vt > 0xFFF or flags > 0xFF:
            return None
        for f in (pfn, pfn_set):
            if f and not img.is_code(f):
                return None
        extra = raw[size:] if stride_extra else b""
        out.append((name, did, params, vt, pfn, pfn_set, off, flags, extra))
    return None


def disp_name(img: cpp.Image, va: int) -> str | None:
    """Name of a dispatch entry: ``LPCTSTR``, so ANSI in an ANSI build and UTF-16 in a Unicode build. A
    one-letter ANSI reading followed by NUL is tried as UTF-16 (letter, NUL, letter, NUL, ...)."""
    nm = img.cstr(va, 130)
    if nm is not None and len(nm) == 1:
        raw = img.read(va, 260)
        if raw is not None and raw[1:2] == b"\x00":
            end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\x00\x00"), -1)
            if end > 2:
                try:
                    wide = raw[:end].decode("utf-16-le")
                except UnicodeDecodeError:
                    return nm
                if _DISP_NAME.match(wide):
                    return wide
    return nm


def _head(img: cpp.Image, addr: int, n: int) -> tuple[int, ...] | None:
    ps = img.psize
    if not img.is_data(addr):
        return None
    vals = tuple(img.ptr(addr + i * ps) for i in range(n))
    if any(v is None for v in vals):
        return None
    base, ents = vals[0], vals[1]
    if base and not (img.is_data(base) or img.is_code(base)):
        return None
    if not img.is_data(ents) or any(v and not img.is_data(v) for v in vals[2:]):
        return None
    return vals


def parse_dispmap(img: cpp.Image, addr: int) -> list[MapEntry] | None:
    head = _head(img, addr, 4)
    if head is None:
        return None
    raw = _disp_entries(img, head[1], 0)
    if raw is None:
        return None
    return [_disp_entry(img, k, e) for k, e in enumerate(raw)]


def parse_eventmap(img: cpp.Image, addr: int) -> list[MapEntry] | None:
    head = _head(img, addr, 3)
    if head is None:
        return None
    raw = _disp_entries(img, head[1], 8)
    if raw is None:
        return None
    return [_disp_entry(img, k, e) for k, e in enumerate(raw)]


def _disp_entry(img: cpp.Image, seq: int, e: tuple) -> MapEntry:
    name, did, params, vt, pfn, pfn_set, off, flags, tail = e
    nm = disp_name(img, name) if name else ""
    extra = []
    if tail:
        first, last = struct.unpack("<II", tail)
        extra.append(f"ctrl {first}" + (f"-{last}" if last not in (first, 0xFFFFFFFF) else ""))
    elif params:
        p = img.read(params, 16) or b""
        p = p.split(b"\0", 1)[0]
        if p:
            extra.append("args " + ",".join(vts_name(c) for c in p))
    if not pfn and nm and not tail:                      # data member (pfn_set: after-set notification)
        extra.append(f"offset 0x{off:x}")
    return MapEntry(seq, nm or "", did, vt, flags, pfn, pfn_set, "; ".join(extra))


def parse_intmap(img: cpp.Image, addr: int) -> list[MapEntry] | None:
    head = _head(img, addr, 2)
    if head is None:
        return None
    ps = img.psize
    allones = 2 ** (8 * ps) - 1
    out: list[MapEntry] = []
    for k in range(MAX_INTF):
        piid = img.ptr(head[1] + 2 * ps * k)
        off = img.ptr(head[1] + 2 * ps * k + ps)
        if piid is None or off is None:
            return None
        if piid == 0 and off == allones:
            return out or None
        raw = img.read(piid, 16) if img.is_data(piid) else None
        if raw is None or off > 0x10000:
            return None
        out.append(MapEntry(k, guid_name(raw), off, 0, 0, 0, 0, ""))
    return None


def kind_of(img: cpp.Image, addr: int, msg_addrs: set[int], cache: dict[int, tuple[str, list[MapEntry]] | None]
            ) -> tuple[str, list[MapEntry]] | None:
    """('dispatch'|'interface'|'event', entries) for a static map at ``addr``; None for anything else
    (message maps included: ``cpp.find_msgmaps`` owns them)."""
    if addr in cache:
        return cache[addr]
    res: tuple[str, list[MapEntry]] | None = None
    if addr not in msg_addrs:
        for kind, fn in ((KIND_DISPATCH, parse_dispmap), (KIND_EVENT, parse_eventmap),
                         (KIND_INTERFACE, parse_intmap)):
            ents = fn(img, addr)
            if ents:
                res = (kind, ents)
                break
    cache[addr] = res
    return res


def mark_connections(img: cpp.Image, getters: list[int | None], msg_addrs: set[int],
                     cache: dict[int, tuple[str, list[MapEntry]] | None]) -> None:
    """Re-label connection maps in ``cache``. ``getters`` are the map addresses returned by the consecutive
    virtual functions of one vtable (None where a slot is no getter). ``GetConnectionMap`` sits right before
    ``GetInterfaceMap`` in a ``CCmdTarget`` vtable and both return the same structure, so two different
    interface-shaped maps in adjacent slots are (connection map, interface map). **[verified]** on the 64-bit
    MFC 4.2 DLL: ``COleControl`` slot 15 has one entry (``IPropertyNotifySink``), slot 16 the control's interfaces."""
    for a, b in zip(getters, getters[1:]):
        if a is None or b is None or a == b:
            continue
        ka, kb = kind_of(img, a, msg_addrs, cache), kind_of(img, b, msg_addrs, cache)
        if ka and kb and ka[0] == KIND_INTERFACE and kb[0] == KIND_INTERFACE:
            cache[a] = (KIND_CONNECTION, ka[1])


# ── names ──────────────────────────────────────────────────────────────────

_VT = {0: "void", 2: "short", 3: "long", 4: "float", 5: "double", 6: "currency", 7: "date", 8: "BSTR",
       9: "IDispatch*", 10: "SCODE", 11: "BOOL", 12: "VARIANT", 13: "IUnknown*", 16: "char", 17: "BYTE",
       18: "WORD", 19: "DWORD", 22: "int", 23: "UINT", 30: "LPSTR", 31: "LPWSTR"}


def vts_name(code: int) -> str:
    """Name of a ``VTS_*`` byte (0x40 = by reference)."""
    if code == 0x4E:                                      # VTS_BSTR: an ANSI string passed as LPCSTR
        return "LPCSTR"
    ref = "&" if code & 0x40 else ""
    return _VT.get(code & 0x3F, f"vt{code & 0x3F}") + ref


def vt_name(vt: int) -> str:
    return _VT.get(vt, f"vt{vt}") if vt != 0xFF else "end"


STOCK_DISPIDS = {
    -500: "Appearance", -501: "BackColor", -502: "BackStyle", -503: "BorderColor", -504: "BorderStyle",
    -505: "BorderWidth", -507: "DrawMode", -508: "DrawStyle", -509: "DrawWidth", -510: "FillColor",
    -511: "FillStyle", -512: "Font", -513: "ForeColor", -514: "Enabled", -515: "hWnd", -516: "TabStop",
    -517: "Text", -518: "Caption", -519: "BorderVisible", -521: "MousePointer", -522: "MouseIcon",
    -523: "Picture", -524: "Valid", -525: "ReadyState", -550: "Refresh", -551: "DoClick", -552: "AboutBox",
    -600: "Click", -601: "DblClick", -602: "KeyDown", -603: "KeyPress", -604: "KeyUp", -605: "MouseDown",
    -606: "MouseMove", -607: "MouseUp", -608: "Error", -609: "ReadyStateChange"}

_IIDS = {
    "00000000-0000-0000-c000-000000000046": "IUnknown",
    "00020400-0000-0000-c000-000000000046": "IDispatch",
    "00000109-0000-0000-c000-000000000046": "IPersistStream",
    "0000010a-0000-0000-c000-000000000046": "IPersistStorage",
    "0000010d-0000-0000-c000-000000000046": "IViewObject",
    "0000010e-0000-0000-c000-000000000046": "IDataObject",
    "00000112-0000-0000-c000-000000000046": "IOleObject",
    "00000113-0000-0000-c000-000000000046": "IOleInPlaceObject",
    "00000117-0000-0000-c000-000000000046": "IOleInPlaceActiveObject",
    "00000126-0000-0000-c000-000000000046": "IRunnableObject",
    "00000127-0000-0000-c000-000000000046": "IViewObject2",
    "b196b284-bab4-101a-b69c-00aa00341d07": "IConnectionPointContainer",
    "b196b286-bab4-101a-b69c-00aa00341d07": "IConnectionPoint",
    "9bfbbc02-eff1-101a-84ed-00aa00341d07": "IPropertyNotifySink",
    "b196b283-bab4-101a-b69c-00aa00341d07": "IProvideClassInfo",
    "b196b288-bab4-101a-b69c-00aa00341d07": "IOleControl",
    "b196b28b-bab4-101a-b69c-00aa00341d07": "ISpecifyPropertyPages",
    "7fd52380-4e07-101b-ae2d-08002b2ec713": "IPersistStreamInit",
    "37d84f60-42cb-11ce-8135-00aa004bb851": "IPersistPropertyBag",
    "376bd3aa-3845-101b-84ed-08002b2ec713": "IPerPropertyBrowsing",
    "cf51ed10-62fe-11cf-bf86-00a0c9034836": "IQuickActivate"}


def guid_text(raw: bytes) -> str:
    d1, d2, d3 = struct.unpack("<IHH", raw[:8])
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}"


def guid_name(raw: bytes) -> str:
    g = guid_text(raw)
    return _IIDS.get(g, "{" + g.upper() + "}")


_BAD = re.compile(r"[^A-Za-z0-9]+")


def ident(text: str, limit: int = 24) -> str:
    """A C identifier part from a caption: ``&Save As...`` -> ``Save_As``."""
    t = text.split("\t")[0].replace("&", "")
    t = _BAD.sub("_", t).strip("_")
    return t[:limit].strip("_")


# ── analysis ───────────────────────────────────────────────────────────────

@dataclass
class MfcClass:
    name: str
    vtable: int
    rc: int                       # CRuntimeClass address, 0 when none
    size: int
    schema: int
    base: str
    map_addr: int                 # message map, 0 when none
    dialog: str                   # resource id of the dialog passed to the CDialog constructor
    source: str                   # rc | dialog | inherited


@dataclass
class Mfc:
    classes: list[MfcClass] = field(default_factory=list)
    maps: list[ExtraMap] = field(default_factory=list)


_CALL_AFTER_PUSH = re.compile(rb"(?:\x68(....)|\x6a(.)).{0,6}?\xe8(....)", re.S)


_ID64 = re.compile(rb"(?:\xba(....)|\x41\xb8(....)).{0,14}?\xe8(....)", re.S)
_LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](....)", re.S)


def _stores_vtable(lea: bytes, tail: bytes) -> bool:
    """``tail`` (the bytes after ``lea reg, [rip+d]``) starts, within 4 bytes, with ``mov [reg2], reg`` (mod 00,
    no SIB or disp32): the store of the vtable pointer to offset 0 of the object."""
    reg = ((lea[2] >> 3) & 7) | ((lea[0] & 4) << 1)
    for k in range(0, 5):
        if k + 2 < len(tail) and tail[k] in (0x48, 0x49, 0x4C, 0x4D) and tail[k + 1] == 0x89:
            md = tail[k + 2]
            if md & 0xC0 == 0 and md & 7 not in (4, 5) and ((md >> 3) & 7) | ((tail[k] & 4) << 1) == reg:
                return True
    return False


def ctor_dialogs(img: cpp.Image, vtables: Iterable[int], dialog_ids: set[int]) -> dict[int, int]:
    """vtable -> dialog resource id passed to the base constructor: the constructor loads the id, calls
    ``CDialog::CDialog`` and then stores the vtable pointer. The id must be a dialog of the binary, and the
    call target must be shared by at least two classes. 32-bit: ``push id`` and ``mov [reg], vtable``;
    64-bit: ``mov edx, id`` (or ``mov r8d, id``) and ``lea reg, [rip+vtable]; mov [reg2], reg``."""
    if not dialog_ids:
        return {}
    found = _ctor_dialogs32(img, vtables, dialog_ids) if img.psize == 4 else _ctor_dialogs64(img, vtables, dialog_ids)
    targets: dict[int, int] = {}
    for _imm, tgt in found.values():
        targets[tgt] = targets.get(tgt, 0) + 1
    return {vt: imm for vt, (imm, tgt) in found.items() if targets[tgt] >= 2}


def _ctor_dialogs32(img: cpp.Image, vtables: Iterable[int], dialog_ids: set[int]) -> dict[int, tuple[int, int]]:
    code = [(s.va, s.data) for s in img.sections if s.executable]
    found: dict[int, tuple[int, int]] = {}
    for vt in vtables:
        pat = struct.pack("<I", vt)
        for va, data in code:
            i = data.find(pat)
            while i >= 0:
                if i >= 2 and data[i - 2] == 0xC7 and data[i - 1] & 0xF8 == 0 and data[i - 1] not in (4, 5):
                    lo = max(0, i - 2 - 96)
                    seg = data[lo:i - 2]
                    best = None
                    for m in _CALL_AFTER_PUSH.finditer(seg):
                        if len(seg) - m.end() > CALL_TO_STORE:        # the call of an earlier function
                            continue
                        imm = struct.unpack("<I", m.group(1))[0] if m.group(1) else m.group(2)[0]
                        if imm in dialog_ids:
                            tgt = (va + lo + m.end() + struct.unpack("<i", m.group(3))[0]) & 0xFFFFFFFF
                            best = (imm, tgt)
                    if best:
                        found[vt] = best
                        break
                i = data.find(pat, i + 1)
            if vt in found:
                break
    return found


def _ctor_dialogs64(img: cpp.Image, vtables: Iterable[int], dialog_ids: set[int]) -> dict[int, tuple[int, int]]:
    want = set(vtables)
    found: dict[int, tuple[int, int]] = {}
    for va, data in ((s.va, s.data) for s in img.sections if s.executable):
        for lm in _LEA_RIP.finditer(data):
            i = lm.start()
            vt = (va + i + 7 + struct.unpack("<i", lm.group(1))[0]) & 0xFFFFFFFFFFFFFFFF
            if vt not in want or vt in found or not _stores_vtable(data[i:i + 3], data[i + 7:i + 14]):
                continue
            lo = max(0, i - 96)
            seg = data[lo:i]
            best = None
            for m in _ID64.finditer(seg):
                if len(seg) - m.end() > CALL_TO_STORE:                # the call of an earlier function
                    continue
                imm = struct.unpack("<I", m.group(1) or m.group(2))[0]
                if imm in dialog_ids:
                    best = (imm, (va + lo + m.end() + struct.unpack("<i", m.group(3))[0]) & 0xFFFFFFFFFFFFFFFF)
            if best:
                found[vt] = best
    return found


def _dialog_ids(path: Path | None) -> dict[int, str]:
    """Numeric dialog resource id -> caption (cleaned)."""
    if path is None:
        return {}
    try:
        from airlock.server import peres
        parsed = peres.parse_file(path)
    except Exception:  # noqa: BLE001  an extra
        return {}
    out: dict[int, str] = {}
    for did, _lang, dlg in (parsed.dialogs if parsed else []):
        if str(did).isdigit():
            out.setdefault(int(did), dlg.caption or "")
    return out


_DIALOGISH = re.compile(r"Dialog|Page|FormView|Sheet|Wizard")
_SYM_IDENT = re.compile(r"^[A-Za-z_]\w*$")


def symbol_class(symbols: dict[int, str], fns: Iterable[int], framework: set[str]) -> str | None:
    """The class name that most functions of ``fns`` (handlers, virtual functions) carry as namespace, when
    it is clear: at least two functions, at least two thirds of the namespaced ones, an identifier, and no
    framework class (the inherited virtual functions belong to the base)."""
    votes: dict[str, int] = {}
    for f in dict.fromkeys(fns):
        ns = symbols.get(f)
        if ns and ns not in framework and _SYM_IDENT.match(ns) and not ns.startswith(cpp.ANON_PREFIX):
            votes[ns] = votes.get(ns, 0) + 1
    if not votes:
        return None
    best = max(votes, key=votes.get)                                  # type: ignore[arg-type]
    return best if votes[best] >= 2 and votes[best] * 3 >= 2 * sum(votes.values()) else None


def map_dialog(entries: list[cpp.MsgEntry], ctrls: dict[int, set[int]]) -> int | None:
    """The one dialog whose controls include every command / notification id of a map (single ids only; at
    least one id above IDHELP). None when no dialog or several fit."""
    ids = {e.id for e in entries if e.message in (0x111, 0x4E) and e.id == e.last_id
           and e.id not in (0, 0xFFFF, 0xFFFFFFFF)}
    if not any(i > 9 for i in ids):
        return None
    fit = [d for d, c in ctrls.items() if ids <= c]
    return fit[0] if len(fit) == 1 else None


def _dialog_ctrls(path: Path | None) -> dict[int, set[int]]:
    """Numeric dialog resource id -> ids of its controls."""
    if path is None:
        return {}
    try:
        from airlock.server import peres
        parsed = peres.parse_file(path)
    except Exception:  # noqa: BLE001  an extra
        return {}
    out: dict[int, set[int]] = {}
    for did, _lang, dlg in (parsed.dialogs if parsed else []):
        if str(did).isdigit():
            out.setdefault(int(did), set()).update(c.ctrl_id for c in dlg.controls)
    return out


def _base_map(img: cpp.Image, gt: Getters, addr: int) -> int | None:
    b = img.ptr(addr)
    if not b:
        return None
    if img.is_code(b):
        return gt.of(b)
    return b


def analyse(img: cpp.Image, classes: list[cpp.RttiClass], slots: dict[int, list[int]],
            maps: list[cpp.MsgMap], artifact: Path | None = None,
            symbols: dict[int, str] | None = None) -> Mfc:
    """Names anonymous message map classes in place (``maps``) and returns the class rows and the
    dispatch / interface / event / connection maps. ``symbols``: function entry -> class (namespace) the
    disassembler gave it (a PDB, exports, renames); the evidence for ``symbol_class``."""
    gt = Getters(img)
    msg_addrs = {m.map_addr for m in maps}
    by_addr = {m.map_addr: m for m in maps}
    cache: dict[int, tuple[str, list[MapEntry]] | None] = {}
    res = Mfc()

    def extra_in(fns: Iterable[int]) -> list[tuple[int, str, list[MapEntry]]]:
        out: list[tuple[int, str, list[MapEntry]]] = []
        seen: set[int] = set()
        fns = list(fns)
        mark_connections(img, [gt.of(f) for f in fns], msg_addrs, cache)
        for f in fns:
            a = gt.of(f)
            if a is None or a in seen:
                continue
            k = kind_of(img, a, msg_addrs, cache)
            if k is not None:
                seen.add(a)
                out.append((a, k[0], k[1]))
        return out

    # RTTI classes: same ownership rule as the message maps
    owners: dict[int, list[cpp.RttiClass]] = {}
    for c in classes:
        if c.vtable is None or c.offset != 0:
            continue
        for a, _k, _e in extra_in(slots.get(c.vtable, ())):
            if c not in owners.setdefault(a, []):
                owners[a].append(c)
    anc = cpp._ancestors(classes)
    for a, cs in sorted(owners.items()):
        if len(cs) > 1:
            top = [c for c in cs if all(c.name == o.name or c.name in anc.get(o.name, ()) for o in cs)]
            cs = top or cs
        kind, ents = cache[a]                                             # type: ignore[misc]
        for name in dict.fromkeys(c.name for c in cs):
            res.maps.append(ExtraMap(name, kind, a, ents))

    # route tables (MFC look-alike): the vtable of the GetRouteTable slot, the base table's class
    route_names = {m.map_addr: m.cls for m in maps if m.kind == "routes"}
    for m in maps:
        if m.kind == "routes" and m.vtable:
            res.classes.append(MfcClass(m.cls, m.vtable, 0, 0, 0, route_names.get(m.base_map, ""), m.map_addr,
                                        "", "routes"))

    # classes without RTTI: through the CRuntimeClass slot
    rcs = find_runtime_classes(img)
    if not rcs:
        return res
    rtti_starts = {c.vtable for c in classes if c.vtable is not None}
    groups = find_groups(img, rcs, gt, rtti_starts)
    owner = decide_owners(groups)
    owned = {id(g) for g in owner.values()}
    for g in groups:
        mark_connections(img, [gt.of(f) for f in g.fns], msg_addrs, cache)
        for a in dict.fromkeys(x for x in (gt.of(f) for f in g.fns) if x is not None):
            if a in by_addr:
                g.maps.setdefault("msg", []).append(a)
            else:
                k = kind_of(img, a, msg_addrs, cache)
                if k is not None:
                    g.maps.setdefault(k[0], []).append(a)
    # who may own a map: the owner group; a map shared through an inherited slot goes to the claimer whose
    # CRuntimeClass is an ancestor of all the others
    holders: dict[int, int] = {}
    claim: dict[int, list[Group]] = {}
    for g in groups:
        for ms in g.maps.values():
            for a in ms:
                holders[a] = holders.get(a, 0) + 1
                if not g.rtti and id(g) in owned:
                    claim.setdefault(a, []).append(g)

    def ancestor_rcs(rc: RuntimeClass) -> set[int]:
        out: set[int] = set()
        while rc.base in rcs and rc.base not in out:
            out.add(rc.base)
            rc = rcs[rc.base]
        return out

    owner_of: dict[int, Group] = {}                     # map address -> its owner group
    for a, gs in claim.items():
        pick = gs
        if len(gs) > 1:
            top = [g for g in gs if all(g is o or g.rc.addr in ancestor_rcs(o.rc) for o in gs)]
            pick = top if len(top) == 1 else []
        if len(pick) == 1:
            owner_of[a] = pick[0]
    for a, g in owner_of.items():
        m = by_addr.get(a)
        if m is not None and m.cls.startswith(cpp.ANON_PREFIX):
            m.cls = g.rc.name

    # the disassembler's own class name for the handlers and virtual functions: the clearest evidence
    sym_map: dict[int, Group] = {}                      # anonymous map -> group named from symbols
    if symbols:
        taken = {m.cls for m in maps} | {c.name for c in classes} | {r.name for r in rcs.values()}
        for g in sorted(groups, key=lambda x: x.start):
            if g.rtti or id(g) in owned:
                continue
            for a in g.maps.get("msg", ()):
                m = by_addr[a]
                if m.cls.startswith(cpp.ANON_PREFIX) and holders[a] == 1:
                    nm = symbol_class(symbols, [e.handler for e in m.entries] + g.fns, {r.name for r in rcs.values()})
                    if nm and nm not in taken:
                        taken.add(nm)
                        m.cls = nm
                        sym_map[a] = g
                        break

    dialogs = _dialog_ids(artifact)
    gdlg = ctor_dialogs(img, {g.start for g in groups if not g.rtti}, set(dialogs))
    dlg_map: dict[int, Group] = {}                      # anonymous map -> dialog group naming it
    used: dict[str, int] = {}

    def dialog_name(did: int) -> str:
        cap = ident(dialogs.get(did, ""))
        nm = f"Dialog_{cap}" if cap else f"Dialog_{did}"
        used[nm] = used.get(nm, 0) + 1
        return nm if used[nm] == 1 else f"{nm}_{did}"

    for g in sorted(groups, key=lambda x: x.start):
        if g.rtti or g.start not in gdlg:
            continue
        for a in g.maps.get("msg", ()):
            m = by_addr[a]
            if m.cls.startswith(cpp.ANON_PREFIX) and holders[a] == 1:
                m.cls = dialog_name(gdlg[g.start])
                dlg_map[a] = g
                break
    # a dialog class whose constructor was not recognised: the dialog that holds every control id of its map
    ctrls = _dialog_ctrls(artifact) if dialogs else {}
    for g in sorted(groups, key=lambda x: x.start):
        if g.rtti or id(g) in owned or g.start in gdlg or not _DIALOGISH.search(g.rc.name):
            continue
        for a in g.maps.get("msg", ()):
            m = by_addr[a]
            if m.cls.startswith(cpp.ANON_PREFIX) and holders[a] == 1:
                did = map_dialog(m.entries, ctrls)
                if did is not None:
                    gdlg[g.start] = did
                    m.cls = dialog_name(did)
                    dlg_map[a] = g
                    break
    inherit_map: dict[int, Group] = {}                  # anonymous map -> group of a class derived from rc
    for g in sorted(groups, key=lambda x: x.start):
        if g.rtti or id(g) in owned:
            continue
        for a in g.maps.get("msg", ()):
            m = by_addr[a]
            if m.cls.startswith(cpp.ANON_PREFIX) and holders[a] == 1:
                m.cls = f"{cpp.ANON_PREFIX}{g.rc.name}_{a:0{2 * img.psize}x}"
                inherit_map[a] = g
                break

    # rows
    names = {m.map_addr: m.cls for m in maps}
    for g in sorted(groups, key=lambda x: x.start):
        if g.rtti:
            continue
        own_map = next((a for a in g.maps.get("msg", ()) if owner_of.get(a) is g or dlg_map.get(a) is g
                                                                or inherit_map.get(a) is g or sym_map.get(a) is g), 0)
        is_owner = id(g) in owned
        if not (is_owner or own_map):
            continue
        base = ""
        if own_map:
            bm = _base_map(img, gt, own_map)
            base = names.get(bm, "") if bm else ""
        if not base:
            base = (rcs[g.rc.base].name if g.rc.base in rcs else "") if is_owner else g.rc.name
        label = g.rc.name if is_owner else names[own_map]
        dlg = str(gdlg[g.start]) if g.start in gdlg else ""
        res.classes.append(MfcClass(label, g.start, g.rc.addr if is_owner else 0,
                                    g.rc.size if is_owner else 0, g.rc.schema if is_owner else 0, base,
                                    own_map, dlg, "rc" if is_owner else ("symbols" if sym_map.get(own_map) is g
                                                                 else ("dialog" if dlg else "inherited"))))
        for kind in EXTRA_KINDS:
            for a in g.maps.get(kind, ()):
                k = cache[a]
                if k is not None and owner_of.get(a) is g:
                    res.maps.append(ExtraMap(label, kind, a, k[1]))
    # one row per (class, kind, address)
    seen: set[tuple[str, str, int]] = set()
    uniq: list[ExtraMap] = []
    for em in res.maps:
        key = (em.cls, em.kind, em.addr)
        if key not in seen:
            seen.add(key)
            uniq.append(em)
    res.maps = uniq
    return res
