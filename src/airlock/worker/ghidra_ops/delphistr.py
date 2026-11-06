"""Delphi string literals in the decompiled C (post-analysis fixup, DESIGN 11 "Delphi string literals").

A Delphi 2009+ ``UnicodeString`` / ``AnsiString`` literal is a constant ``StrRec`` header followed by the
characters and a terminating zero; code passes the address of the characters::

    [x64 only: u32 padding] u16 codePage; u16 elemSize; i32 refCnt = -1; i32 length; chars...; 0

A ``ShortString`` literal is a length byte followed by the characters; code passes the length byte's
address. Ghidra's own string analysis often types the characters as ``unicode`` already, but the
decompiler still prints ``FUN_00412a40(local_28, 0x124ab50)`` because Parameter ID typed the callee's
parameter as ``longlong``: a constant is turned into a string only for a pointer (or undefined)
parameter. **[verified]** (Ghidra 12.1.4, a Delphi 12 x64 program) retyping that parameter to
``wchar_t *`` or ``undefined8`` gives ``FUN_00412a40(local_28, L"TABLES WITH READ LOCK")``.

The pass (inside the caller's transaction): find the literals by their header (or, for ShortStrings,
by a data reference to a length-prefixed text in code memory), type the characters as string data where
nothing is defined, then follow each instruction reference to the call it feeds (``LEA RDX,[lit]`` ...
``CALL f``) and retype that register parameter of ``f`` from an integer to a string pointer.
Parameters of user-defined signatures and pointer parameters are left alone.

``scan_strrec`` / ``shortstring_at`` are pure (bytes in, literals out) and unit-tested.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

UNICODE_CP = 1200
MAX_CHARS = 1 << 20
MIN_SHORT = 3            # ShortString literals shorter than this are not trusted
CALL_WINDOW = 8          # instructions between the reference and the call
MIN_LITERALS = 16        # fewer header matches: not a Delphi 2009+ program, nothing is changed

# codePage(2) elemSize(2)=1|2 refCnt(4)=-1: the 8 bytes that end 4 bytes before the characters
_STRREC = re.compile(rb"(?s)..[\x01\x02]\x00\xff\xff\xff\xff")
_TEXT_OK = re.compile(r"[^\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]*\Z")


def _printable(text: str) -> bool:
    return bool(text) and _TEXT_OK.match(text) is not None


def scan_strrec(buf: bytes, base: int = 0) -> Iterator[tuple[int, str, int, str]]:
    """(address of the characters, kind 'u' or 'a', byte length with the terminator, text) of every
    Delphi 2009+ string literal in ``buf`` (mapped at ``base``). The header is the same 12 bytes before
    the characters on 32 and 64 bits (the x64 padding precedes it)."""
    for m in _STRREC.finditer(buf):
        i = m.start()
        elem = buf[i + 2]
        cp = int.from_bytes(buf[i:i + 2], "little")
        if elem == 2 and cp != UNICODE_CP:
            continue
        if i + 12 > len(buf):
            break
        n = int.from_bytes(buf[i + 8:i + 12], "little", signed=True)
        if n <= 0 or n > MAX_CHARS:
            continue
        a = i + 12
        end = a + n * elem
        if end + elem > len(buf) or any(buf[end:end + elem]):
            continue
        raw = buf[a:end]
        try:
            text = raw.decode("utf-16-le") if elem == 2 else raw.decode("latin-1")
        except UnicodeDecodeError:
            continue
        if "\x00" in text or not _printable(text):
            continue
        yield base + a, "u" if elem == 2 else "a", n * elem + elem, text


_IDENT_B = re.compile(rb"[\w.<>,@$&:]+\Z")


def shortstring_at(buf: bytes, off: int) -> str | None:
    """Text of a ShortString literal at ``buf[off]`` (length byte, then printable ASCII), or None.
    Identifiers are refused: code also points at RTTI type names (``Integer``) and at type info records
    (kind byte, then a ShortString name), which read as a ShortString of the kind's length. **[verified]**
    without this rule most hits in two Delphi programs were type info."""
    if off >= len(buf):
        return None
    n = buf[off]
    if n < MIN_SHORT or off + 1 + n > len(buf):
        return None
    raw = buf[off + 1:off + 1 + n]
    if any(c < 0x20 or c > 0x7e for c in raw) or _IDENT_B.match(raw):
        return None
    m = raw[0]          # a nested length byte followed by an identifier: a type info record
    if off + 2 + m <= len(buf) and _IDENT_B.match(buf[off + 2:off + 2 + m]):
        return None
    return raw.decode("ascii")


# ── Ghidra side ────────────────────────────────────────────────────────────

def _block_bytes(blk: Any) -> bytes:
    import jpype
    buf = jpype.JArray(jpype.JByte)(int(blk.getSize()))
    blk.getBytes(blk.getStart(), buf)
    return bytes(memoryview(buf).cast("B"))


def _string_type(kind: str, nbytes: int) -> Any:
    from ghidra.program.model.data import (PascalString255DataType, StringDataType,  # type: ignore
                                           UnicodeDataType)
    if kind == "u":
        return UnicodeDataType.dataType
    if kind == "a":
        return StringDataType.dataType
    return PascalString255DataType.dataType


def _define(listing: Any, addr: Any, kind: str, nbytes: int) -> bool:
    """Type the literal as string data when nothing but undefined bytes is there. True when created."""
    from ghidra.program.model.data import Undefined  # type: ignore
    if listing.getInstructionContaining(addr) is not None:
        return False
    d = listing.getDataContaining(addr)
    if d is not None and d.isDefined():
        if not Undefined.isUndefined(d.getDataType()):
            return False
    end = addr.add(nbytes - 1)
    it = listing.getInstructions(addr, True)
    if it.hasNext() and it.next().getMinAddress().compareTo(end) <= 0:
        return False
    try:
        listing.clearCodeUnits(addr, end, False)
        listing.createData(addr, _string_type(kind, nbytes), nbytes)
        return True
    except Exception:  # noqa: BLE001  defined data in the way: keep it
        return False


def _base(reg: Any) -> Any:
    return reg.getBaseRegister() if reg is not None else None


def _dest_register(ins: Any) -> Any:
    """Register the instruction writes the literal address into (``LEA RDX,[x]``, ``MOV EDX,x``)."""
    mn = str(ins.getMnemonicString()).upper()
    if mn not in ("LEA", "MOV") or ins.getNumOperands() < 2:
        return None
    return ins.getRegister(0)


def _writes(ins: Any, base: Any) -> bool:
    for o in ins.getResultObjects():
        if hasattr(o, "getBaseRegister") and o.getBaseRegister() == base:
            return True
    return False


def _feeds_call(ins: Any, fm: Any) -> tuple[Any, Any] | None:
    """(callee function, base register) when the address loaded by ``ins`` reaches a call's register
    argument: no other write to that register and no branch in between."""
    reg = _dest_register(ins)
    if reg is None:
        return None
    base = _base(reg)
    cur = ins
    for _ in range(CALL_WINDOW):
        cur = cur.getNext()
        if cur is None:
            return None
        ft = cur.getFlowType()
        if ft.isCall():
            flows = cur.getFlows()
            if not flows:
                return None
            f = fm.getFunctionAt(flows[0])
            if f is not None and f.isThunk():
                f = f.getThunkedFunction(True)
            return (f, base) if f is not None and not f.isExternal() else None
        if ft.isJump() or ft.isTerminal() or _writes(cur, base):
            return None
    return None


def _new_type(kinds: set[str], ptr_size: int) -> Any:
    from ghidra.program.model.data import (CharDataType, PointerDataType,  # type: ignore
                                           Undefined, WideCharDataType)
    if kinds == {"u"}:
        return PointerDataType(WideCharDataType.dataType, ptr_size)
    if kinds == {"a"}:
        return PointerDataType(CharDataType.dataType, ptr_size)
    return Undefined.getUndefinedDataType(ptr_size)


def _retypable(p: Any, ptr_size: int) -> bool:
    from ghidra.program.model.data import AbstractIntegerDataType, Pointer, Undefined  # type: ignore
    dt = p.getDataType()
    if isinstance(dt, Pointer) or int(dt.getLength()) != ptr_size:
        return False
    return Undefined.isUndefined(dt) or isinstance(dt, AbstractIntegerDataType)


def apply_delphi_strings(program: Any, monitor: Any = None) -> dict[str, int]:
    """Define Delphi string literals and retype the call parameters that receive them. Idempotent; must
    run inside a transaction. Programs without StrRec literals cost one byte scan of their blocks."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    mem = program.getMemory()
    listing = program.getListing()
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    sp = program.getAddressFactory().getDefaultAddressSpace()
    ptr_size = int(sp.getPointerSize())
    lits: dict[int, tuple[str, int]] = {}
    bufs: list[tuple[int, bytes]] = []
    for blk in mem.getBlocks():
        if not blk.isInitialized() or blk.isOverlay() or blk.isWrite() and not blk.isExecute():
            continue
        try:
            buf = _block_bytes(blk)
        except Exception:  # noqa: BLE001  unreadable block
            continue
        start = int(blk.getStart().getOffset())
        bufs.append((start, buf))
        for a, kind, nbytes, _text in scan_strrec(buf, start):
            lits[a] = (kind, nbytes)
    out = {"literals": len(lits), "short": 0, "defined": 0, "sites": 0, "params": 0}
    if len(lits) < MIN_LITERALS:
        return out          # not a Delphi 2009+ program (or chance matches): change nothing
    # ShortString literals: data references from code to a length-prefixed text in a scanned block
    for start, buf in bufs:
        if monitor is not None and monitor.isCancelled():
            break
        rng = program.getAddressFactory().getAddressSet(sp.getAddress(start), sp.getAddress(start + len(buf) - 1))
        it = refman.getReferenceDestinationIterator(rng, True)
        while it.hasNext():
            dst = it.next()
            off = int(dst.getOffset()) - start
            text = shortstring_at(buf, off)     # pure check first: most destinations are code
            if text is None or (start + off) in lits or (start + off + 1) in lits \
                    or listing.getInstructionContaining(dst) is not None:
                continue
            if any(r.getReferenceType().isData() and listing.getInstructionAt(r.getFromAddress()) is not None
                   for r in refman.getReferencesTo(dst)):
                lits[start + off] = ("s", len(text) + 1)
                out["short"] += 1
    by_param: dict[tuple[int, int], set[str]] = {}
    funcs: dict[int, Any] = {}
    for a, (kind, nbytes) in lits.items():
        if monitor is not None and monitor.isCancelled():
            break
        addr = sp.getAddress(a)
        if _define(listing, addr, kind, nbytes):
            out["defined"] += 1
        if kind == "s":
            continue        # a ShortString pointer is no C string: the data label is what shows
        for r in refman.getReferencesTo(addr):
            ins = listing.getInstructionAt(r.getFromAddress())
            if ins is None:
                continue
            hit = _feeds_call(ins, fm)
            if hit is None:
                continue
            f, base = hit
            for p in f.getParameters():
                reg = p.getRegister()
                if reg is not None and _base(reg) == base:
                    key = (int(f.getEntryPoint().getOffset()), int(p.getOrdinal()))
                    by_param.setdefault(key, set()).add(kind)
                    funcs[key[0]] = f
                    out["sites"] += 1
                    break
    for (entry, ordinal), kinds in by_param.items():
        f = funcs[entry]
        if f.getSignatureSource() == SourceType.USER_DEFINED:
            continue
        p = f.getParameter(ordinal)
        if p is None or not _retypable(p, ptr_size):
            continue
        try:
            p.setDataType(_new_type(kinds, ptr_size), SourceType.ANALYSIS)
            out["params"] += 1
        except Exception:  # noqa: BLE001  one odd signature must not stop the pass
            continue
    return out
