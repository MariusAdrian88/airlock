"""Delphi string literals in the decompiled C (post-analysis fixup, DESIGN 11 "Delphi string literals").

A Delphi 2009+ ``UnicodeString`` / ``AnsiString`` literal is a constant ``StrRec`` header followed by the
characters and a terminating zero; code passes the address of the characters::

    [x64 only: u32 padding] u16 codePage; u16 elemSize; i32 refCnt = -1; i32 length; chars...; 0

Free Pascal writes the same header on 32 bits; on 64 bits it is 24 bytes (``u16 codePage; u16 elemSize;
u32 padding; i64 refCount = -1; i64 length``), handled by ``scan_strrec64``. Its concatenation routines
take an open array (the pieces are stores into a stack array, which the decompiler already shows), or fixed
register parameters, so they need no stub.

Delphi 2007 and older write the shorter header ``i32 refCnt = -1; i32 length`` before an ``AnsiString``
literal and a ``WideString`` literal as ``u32 byteLength; wide chars...; u16 0`` (no reference count).
A ``ShortString`` literal is a length byte followed by the characters; code passes the length byte's
address. Ghidra's own string analysis often types the characters as ``unicode`` already, but the
decompiler still prints ``FUN_00412a40(local_28, 0x124ab50)`` because Parameter ID typed the callee's
parameter as ``longlong``: a constant is turned into a string only for a pointer (or undefined)
parameter. **[verified]** (Ghidra 12.1.4, a Delphi 12 x64 program) retyping that parameter to
``wchar_t *`` or ``undefined8`` gives ``FUN_00412a40(local_28, L"TABLES WITH READ LOCK")``.

The pass (inside the caller's transaction): find the literals by their header (or, for ShortStrings,
by a data reference to a length-prefixed text in code memory), type the characters as string data where
nothing or only stray instructions are, then follow each instruction reference to the call it feeds
(``LEA RDX,[lit]`` ... ``CALL f``; ``PUSH lit`` / ``MOV [RSP+0x20],RAX`` for stack arguments) and retype
that parameter of ``f`` from an integer to a string pointer. Parameters of user-defined signatures and
pointer parameters are left alone. String concatenation routines (``UStrCatN`` and its kin: a count in
EDX and that many pieces after it) get a variadic signature on x64, where the decompiler then shows the
pieces; on x86 the routine pops its own variable argument list, the decompiler loses the pushed pieces,
and the pass writes them as a PRE comment at the call instead.

``scan_strrec`` / ``scan_old`` / ``shortstring_at`` / ``literal_use`` / ``is_concat`` /
``concat_comment`` are pure and unit-tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

from .stubs import STUB_BLOCK, STUB_TAG, in_stubs as _in_stubs, rename_all as _rename_stubs, stub_name  # noqa: F401

UNICODE_CP = 1200
MAX_CHARS = 1 << 20
MIN_SHORT = 3            # ShortString literals shorter than this are not trusted
CALL_WINDOW = 16         # instructions between the reference and the call
MIN_LITERALS = 16        # fewer header matches: not a Delphi program, nothing is changed
CONCAT_WINDOW = 48       # instructions searched backwards for the pushed pieces of a concatenation
CONCAT_MARK = "concat "  # PRE comments the pass writes start with this; it replaces only its own
STUB_STRIDE = 16
STUB_SLOTS = 1024         # stubs a new block holds: one per (routine, piece count)
GROW_SLOTS = 2048         # slots a full block grows by (joined to the block's end)
MAX_SLOTS = 8192          # stubs per program, all kinds
MAX_STUB_PIECES = 255     # the count of a concatenation call is a byte
MAX_VCALL_STUBS = 4096    # stubs for indirect calls of x86 Pascal code (virtual and interface methods)
VCALL_WINDOW = 12         # instructions searched backwards for the register arguments of such a call
VERSION = 7              # of the pass; stored in the program (options "airlock", delphi_strings)

# codePage(2) elemSize(2)=1|2 refCnt(4)=-1: the 8 bytes that end 4 bytes before the characters
_STRREC = re.compile(rb"(?s)..[\x01\x02]\x00\xff\xff\xff\xff")
# Free Pascal x64: codePage(2) elemSize(2)=1|2 padding(4) refCount(8)=-1
_STRREC64 = re.compile(rb"(?s)..[\x01\x02]\x00....\xff{8}")
# Delphi 2007 and older: refCnt(4)=-1 then the length
_OLDREC = re.compile(rb"(?=\xff\xff\xff\xff)")
# WideString: even byte length below 2 MB, then a first character in ASCII
_WIDEREC = re.compile(rb"(?s)(?=.[\x00-\x1f]\x00\x00[\x20-\x7e]\x00)")
_TEXT_OK = re.compile(r"[^\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]*\Z")


def _printable(text: str) -> bool:
    return bool(text) and _TEXT_OK.match(text) is not None


def _strrec_text(buf: bytes, base: int, i: int, a: int, n: int) -> tuple[int, str, int, str] | None:
    """The literal whose header starts at ``buf[i]`` (code page, element size), ``n`` characters at ``a``."""
    elem = buf[i + 2]
    if elem == 2 and int.from_bytes(buf[i:i + 2], "little") != UNICODE_CP:
        return None
    if n <= 0 or n > MAX_CHARS:
        return None
    end = a + n * elem
    if end + elem > len(buf) or any(buf[end:end + elem]):
        return None
    raw = buf[a:end]
    try:
        text = raw.decode("utf-16-le") if elem == 2 else raw.decode("latin-1")
    except UnicodeDecodeError:
        return None
    if "\x00" in text or not _printable(text):
        return None
    return base + a, "u" if elem == 2 else "a", n * elem + elem, text


def scan_strrec(buf: bytes, base: int = 0) -> Iterator[tuple[int, str, int, str]]:
    """(address of the characters, kind 'u' or 'a', byte length with the terminator, text) of every
    Delphi 2009+ (and Free Pascal 32-bit) string literal in ``buf`` (mapped at ``base``). The header is the
    same 12 bytes before the characters on 32 and 64 bits (the Delphi x64 padding precedes it)."""
    for m in _STRREC.finditer(buf):
        i = m.start()
        if i + 12 > len(buf):
            break
        hit = _strrec_text(buf, base, i, i + 12, int.from_bytes(buf[i + 8:i + 12], "little", signed=True))
        if hit is not None:
            yield hit


def scan_strrec64(buf: bytes, base: int = 0) -> Iterator[tuple[int, str, int, str]]:
    """As ``scan_strrec`` for the Free Pascal 64-bit header, 24 bytes before the characters:
    ``u16 codePage; u16 elemSize; u32 padding; i64 refCount = -1; i64 length``."""
    for m in _STRREC64.finditer(buf):
        i = m.start()
        if i + 24 > len(buf):
            break
        hit = _strrec_text(buf, base, i, i + 24, int.from_bytes(buf[i + 16:i + 24], "little", signed=True))
        if hit is not None:
            yield hit


def _ascii_pairs(text: str) -> bool:
    """True when most characters of a wide text are two ASCII bytes: 8-bit text read as UTF-16."""
    pairs = sum(1 for c in text if 0x20 <= (ord(c) >> 8) <= 0x7e)
    return pairs * 2 > len(text)


def scan_old(buf: bytes, base: int = 0) -> Iterator[tuple[int, str, int, str]]:
    """Literals of Delphi 2007 and older, as ``scan_strrec``: ``AnsiString`` (``i32 -1, i32 length,
    chars, 0``, kind 'a') and ``WideString`` (``u32 byte length, wide chars, u16 0``, kind 'u'). The
    headers are 4-byte aligned. Both shapes also occur in other data, so the caller keeps only literals
    that code references, and only in a program with enough of them."""
    ansi: set[int] = set()
    for m in _OLDREC.finditer(buf):
        i = m.start()
        if (base + i) % 4 or i + 8 > len(buf):
            continue
        n = int.from_bytes(buf[i + 4:i + 8], "little", signed=True)
        a = i + 8
        if n <= 0 or n > MAX_CHARS or a + n >= len(buf) or buf[a + n]:
            continue
        text = buf[a:a + n].decode("latin-1")
        if "\x00" in text or "\x7f" in text or not _printable(text):
            continue
        ansi.add(base + a)
        yield base + a, "a", n + 1, text
    for m in _WIDEREC.finditer(buf):
        i = m.start()
        nb = int.from_bytes(buf[i:i + 4], "little")
        a = i + 4
        if (base + i) % 4 or nb % 2 or nb > 2 * MAX_CHARS or a + nb + 2 > len(buf) \
                or any(buf[a + nb:a + nb + 2]) or (base + a) in ansi:
            continue
        try:
            text = buf[a:a + nb].decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if "\x00" in text or "\x7f" in text or not _printable(text) or _ascii_pairs(text):
            continue
        yield base + a, "u", nb + 2, text


_MARKS = (b"Borland\\Delphi", b"Borland\\Locales", b"CodeGear\\Locales", b"Embarcadero\\Locales")
_MARKS_ALL = _MARKS + tuple(m.decode().encode("utf-16-le") for m in _MARKS)


def delphi_marker(buf: bytes) -> bool:
    """True when ``buf`` holds a registry path of the Delphi RTL (``Software\\Borland\\Locales`` and its
    CodeGear / Embarcadero successors, ``SOFTWARE\\Borland\\Delphi\\RTL``), ANSI or UTF-16."""
    return any(m in buf for m in _MARKS_ALL)


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


# ── instruction walk (pure, on a small view of each instruction) ─────────────

@dataclass(frozen=True)
class Ins:
    """What the walk needs of one instruction. Register names are base registers (``RAX`` for ``EAX`` on
    x64). ``mem`` is a memory destination ``(base register, displacement)``; ``src`` the source register
    of a store or ``PUSH``; ``imm`` an immediate source."""
    mn: str
    dst: str | None = None
    mem: tuple[str, int] | None = None
    src: str | None = None
    imm: int | None = None
    writes: frozenset[str] = frozenset()
    call: bool = False
    jump: bool = False
    pops: int = 0        # x86 call: stack argument slots the callee takes
    bits: int = 32       # width of the destination register (``MOV DL, 1`` writes 8 bits of EDX)
    ld: tuple[str, int] | None = None   # ``MOV reg, [base + disp]``: the memory source


def literal_use(seq: list[Ins], ptr: int) -> tuple[str, Any, int] | None:
    """Where the literal address that ``seq[0]`` loads ends up at the next call: ``('reg', register, i)``
    for a register argument, ``('stack', offset, i)`` for a stack argument (offset in the callee's frame,
    after the return address), ``i`` the index of the call in ``seq``. None when the value is overwritten,
    a branch comes first, or the stack pointer moves under a stack argument."""
    sp = "RSP" if ptr == 8 else "ESP"
    first = seq[0]
    held: str | None = None
    pushed: int | None = None
    disp: int | None = None
    if first.mn == "PUSH":
        pushed = 0
    elif first.mn == "MOV" and first.mem is not None:
        if first.mem[0] != sp:
            return None
        disp = first.mem[1]
    elif first.mn in ("LEA", "MOV") and first.dst:
        held = first.dst
    else:
        return None
    for i, x in enumerate(seq[1:], 1):
        if x.call:
            if held:
                return "reg", held, i
            if pushed is not None:
                return "stack", ptr + ptr * pushed, i
            return "stack", ptr + int(disp or 0), i
        if x.jump:
            return None
        if held:
            if x.mn == "PUSH" and x.src == held:
                held, pushed = None, 0
            elif x.mn == "MOV" and x.mem is not None and x.mem[0] == sp and x.src == held:
                held, disp = None, x.mem[1]
            elif held in x.writes:
                return None
        elif pushed is not None:
            if x.mn == "PUSH":
                pushed += 1
            elif sp in x.writes:
                return None
        elif sp in x.writes:
            return None
    return None


def concat_site(before: list[Ins], ptr: int) -> tuple[int | None, int, list[int]]:
    """(count in EDX, number of pieces passed, indices in ``before`` of the pushed pieces) at a call of a
    possible concatenation routine. ``before`` holds the instructions before the call, nearest first.
    x86: the count is the immediate moved to EDX and the pieces are the pushes; a call in between takes
    its own pushes (``pops``). x64: the pieces are R8, R9 and the stack slots from ``[RSP+0x20]``."""
    n: int | None = None
    idx: list[int] = []
    skip = 0
    slots: set[Any] = set()
    for i, x in enumerate(before):
        if x.jump or (x.call and ptr == 8):
            break
        if x.call:
            skip += x.pops
            continue
        if n is None and ("RDX" in x.writes or "EDX" in x.writes):
            if x.mn != "MOV" or x.imm is None:
                return None, 0, []
            n = x.imm
            continue
        if ptr == 4:
            if x.mn == "PUSH":
                if skip:
                    skip -= 1
                    continue
                idx.append(i)
                if n is not None and len(idx) == n:
                    break
            elif "ESP" in x.writes:
                break
        else:
            for r in ("R8", "R9"):
                if r in x.writes:
                    slots.add(r)
            if x.mn == "MOV" and x.mem is not None and x.mem[0] == "RSP" and x.mem[1] >= 0x20:
                slots.add(x.mem[1])
    return n, (len(idx) if ptr == 4 else len(slots)), idx


def is_concat(sites: list[tuple[int | None, int]]) -> bool:
    """A routine is a string concatenation (``UStrCatN``, ``LStrCatN``, ``WStrCatN``) when at least 3 of
    its calls, and 80% of all, pass a count in EDX and exactly that many pieces."""
    good = sum(1 for n, k in sites if n is not None and 2 <= n <= 255 and k == n)
    return good >= 3 and good * 5 >= len(sites) * 4


_FPC_MARK = re.compile(rb"FPC \d+\.\d+\.\d+ \[")


def fpc_marker(buf: bytes) -> bool:
    """True when ``buf`` holds the version string of the Free Pascal RTL (``FPC 3.2.2 [2021/05/15] for ...``)."""
    return _FPC_MARK.search(buf) is not None


_SAVED = ("EBX", "ESI", "EDI", "EBP")      # registers a prologue pushes to keep them
_NARROW = {("EDX", 8): "DL", ("EDX", 16): "DX", ("ECX", 8): "CL", ("ECX", 16): "CX"}


def vcall_scan(call: Ins, before: list[Ins]) -> tuple[tuple[str, ...], int, bool]:
    """(register arguments, stack arguments, vmt loaded) of an indirect call ``CALL [reg + disp]`` of Free Pascal
    or Delphi x86, whose ``register`` convention passes ``Self`` in EAX, the next arguments in EDX and ECX (a
    hidden result pointer of a string result comes first in Free Pascal, as ``LEA EDX, [local]``, and last in
    Delphi) and the rest on the stack. ``before`` holds the instructions before the call, nearest first; the
    search ends at the previous call or branch, or at the first instruction that is neither a push nor a load
    of EAX, EDX or ECX (a push further back belongs to an outer call, as the code page of a string
    concatenation that the call sits in). A register that the call's own address uses (``MOV ECX, [ECX]`` for
    the vmt) is not an argument; the first write of another base register (Delphi: ``MOV ESI, [EAX]``, then
    ``CALL [ESI + 8]``; or ``MOV EBX, EAX``) is skipped, and after a vmt load (``MOV EBX, [EBX]``) the writes
    that feed it (``MOV EBX, [EBP-8]``) too. A register whose nearest load is a byte or word load
    (``MOV DL, 1``) is named ``DL`` / ``DX`` (``CL`` / ``CX``). A push of EBP is never an argument (EBP is the
    frame pointer, or a variable that a frameless function saves), nor are the pushes of EBX, ESI, EDI at the
    far end when the search stops at the frame set-up or a branch (the prologue saves them). The last value
    tells whether the vmt pointer was loaded just before (``MOV reg, [reg]`` into the base register); EAX is
    always an argument."""
    base = call.mem[0] if call.mem else ""
    wrote: set[str] = set()
    width: dict[str, int] = {}
    pushed: list[str | None] = []
    vmt_seen = False
    vmt_load = False
    stopped = False             # the search ended at a branch or the frame set-up, not at the window or odd code
    for x in before[:VCALL_WINDOW]:
        if x.jump or x.call:
            stopped = x.jump
            break
        if x.mn == "PUSH":
            if x.src != "EBP":
                pushed.append(x.src)
        elif not vmt_seen and base not in ("EAX", "EDX", "ECX") and x.mn == "MOV" and x.dst == base                 and x.mem is None:
            vmt_seen = True     # the vmt load (or a copy of Self): no argument, the search goes on
            vmt_load = x.ld is not None and x.ld[1] == 0
        elif (vmt_load and vmt_seen and x.mn == "MOV" and x.dst == base and x.mem is None
              and base not in ("EAX", "EDX", "ECX")):
            pass                # the chain before a vmt load: ``MOV EBX, [EBP-8]`` that feeds ``MOV EBX, [EBX]``
        elif x.mem is None and x.writes & {"EAX", "EDX", "ECX"}:
            if x.mn == "MOV" and x.dst == base and x.ld == (base, 0):
                vmt_load = True         # MOV EAX, [EAX]
            for r in {"EDX", "ECX"} & x.writes:
                wrote.add(r)
                width.setdefault(r, x.bits if x.dst == r else 32)       # the nearest load decides
        else:
            stopped = x.mn in ("MOV", "ADD", "SUB") and x.dst in ("EBP", "ESP")
            break               # a store or another register: what is further back belongs to other code
    if stopped:
        while pushed and pushed[-1] in _SAVED:
            pushed.pop()        # the oldest pushes of saved registers belong to the prologue
    wrote.discard(base)
    regs = ["EAX"]
    if wrote:
        regs.append("EDX")      # a later register argument needs the earlier ones
        if "ECX" in wrote and base != "EDX":
            regs.append("ECX")
    out = [_NARROW.get((r, width.get(r, 32)), r) for r in regs]
    return tuple(out), len(pushed), vmt_load


def vcall_args(call: Ins, before: list[Ins]) -> tuple[tuple[str, ...], int]:
    """(register arguments, stack arguments) of an indirect call; see ``vcall_scan``."""
    regs, pushes, _vmt = vcall_scan(call, before)
    return regs, pushes


def vcall_key(disp: int, regs: tuple[str, ...], pushes: int) -> str:
    """Identity of a stub for an indirect call; also its tag text."""
    letters = "".join(r[1] if r[0] == "E" else r[0] + ("b" if r[1] == "L" else "w") for r in regs) or "S"
    return f"{disp & 0xFFFFFFFF:x}.{letters}.{pushes}"


def vcall_name(key: str) -> str:
    """Function name of a stub (``vmt_64_ad_0``: vmt offset 0x64, registers EAX and EDX, no stack arguments)."""
    disp, regs, pushes = key.split(".")
    return f"vmt_{disp}_{regs.lower()}_{pushes}"


def _c_quote(kind: str, text: str, limit: int = 60) -> str:
    t = text if len(text) <= limit else text[:limit] + "..."
    t = t.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return ('L"' if kind == "u" else '"') + t + '"'


def piece_storage(ptr: int, i: int, n: int) -> tuple[str, Any]:
    """Where piece ``i`` (0 = first in the string) of an ``n``-piece concatenation call is passed, as the
    callee sees it: ``('reg', name)`` or ``('stack', offset)``. x86 pushes the first piece first, so it
    sits at the highest address; x64 passes R8, R9, then stack slots after the 0x20 bytes of shadow space
    and the return address."""
    if ptr == 4:
        return "stack", 4 + 4 * (n - 1 - i)
    if i < 2:
        return "reg", ("R8", "R9")[i]
    return "stack", 0x28 + 8 * (i - 2)


def concat_comment(pieces: list[tuple[str, str] | None]) -> str:
    """The PRE comment for an x86 concatenation call: pieces in order, literals quoted, others ``?``."""
    return CONCAT_MARK + " + ".join("?" if p is None else _c_quote(*p) for p in pieces)


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


def _stray_code(program: Any, start: Any, end: Any) -> Any:
    """The last address to clear when the instructions over [start, end] are a mis-disassembled literal:
    none starts before ``start``, no function holds them, nothing outside flows into them (the last one
    may run past ``end``). None when real code may be there."""
    listing = program.getListing()
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    prev = listing.getInstructionContaining(start.subtract(1)) if start.getOffset() > 0 else None
    if prev is not None and prev.getFallThrough() is not None \
            and prev.getFallThrough().compareTo(start) >= 0 and prev.getFallThrough().compareTo(end) <= 0:
        return None
    first = listing.getInstructionContaining(start)
    if first is not None and first.getMinAddress().compareTo(start) < 0:
        return None
    last = end
    it = listing.getInstructions(start, True)
    while it.hasNext():
        ins = it.next()
        if ins.getMinAddress().compareTo(end) > 0:
            break
        if fm.getFunctionContaining(ins.getMinAddress()) is not None:
            return None
        for r in refman.getReferencesTo(ins.getMinAddress()):
            if r.getReferenceType().isFlow() and not (start.compareTo(r.getFromAddress()) <= 0
                                                      and r.getFromAddress().compareTo(end) <= 0):
                return None
        if ins.getMaxAddress().compareTo(last) > 0:
            last = ins.getMaxAddress()
    return last


def _define(program: Any, addr: Any, kind: str, nbytes: int, hdr: int) -> int:
    """Type the literal as string data when only undefined bytes, or instructions that are the literal
    disassembled by mistake, are there. 0: kept, 1: defined, 2: defined after clearing stray code."""
    from ghidra.program.model.data import Undefined  # type: ignore
    listing = program.getListing()
    end = addr.add(nbytes - 1)
    d = listing.getDataContaining(addr)
    if d is not None and d.isDefined() and not Undefined.isUndefined(d.getDataType()):
        return 0
    start = addr.subtract(hdr)
    it = listing.getInstructions(start, True)
    nxt = it.next() if it.hasNext() else None
    cleared = 0
    if listing.getInstructionContaining(start) is not None or \
            nxt is not None and nxt.getMinAddress().compareTo(end) <= 0:
        last = None if kind == "s" else _stray_code(program, start, end)
        if last is None:
            return 0
        listing.clearCodeUnits(start, last, False)
        cleared = 1
    try:
        listing.clearCodeUnits(addr, end, False)
        listing.createData(addr, _string_type(kind, nbytes), nbytes)
        return 1 + cleared
    except Exception:  # noqa: BLE001  defined data in the way: keep it
        return 0


def _view(ins: Any, ptr: int, fm: Any = None) -> Ins:
    """The ``Ins`` view of a Ghidra instruction (with ``fm``: the stack slots an x86 callee takes)."""
    from ghidra.program.model.lang import OperandType, Register  # type: ignore
    from ghidra.program.model.scalar import Scalar  # type: ignore

    def base(r: Any) -> str:
        b = r.getBaseRegister()
        return str(b.getName()).upper()

    mn = str(ins.getMnemonicString()).upper()
    ft = ins.getFlowType()
    writes = frozenset(base(o) for o in ins.getResultObjects() if isinstance(o, Register))
    if mn in ("PUSH", "POP", "CALL", "RET"):
        writes = writes | {"RSP" if ptr == 8 else "ESP"}
    dst = mem = src = imm = ld = None
    bits = 32
    n = int(ins.getNumOperands())
    if n >= 1:
        t0 = int(ins.getOperandType(0))
        objs = list(ins.getOpObjects(0))
        if OperandType.isRegister(t0) and not OperandType.isDynamic(t0) and objs:
            if mn == "PUSH":
                src = base(objs[0])
            else:
                dst = base(objs[0])
                bits = int(objs[0].getBitLength())
        elif OperandType.isDynamic(t0):
            regs = [o for o in objs if isinstance(o, Register)]
            disp = sum(int(o.getSignedValue()) for o in objs if isinstance(o, Scalar))
            mem = (base(regs[0]) if len(regs) == 1 else "?", disp)
        elif mn == "PUSH" and OperandType.isScalar(t0) and objs:
            imm = int(objs[0].getUnsignedValue())
    if n >= 2 and mn in ("MOV", "LEA"):
        t1 = int(ins.getOperandType(1))
        objs = list(ins.getOpObjects(1))
        if OperandType.isRegister(t1) and not OperandType.isDynamic(t1) and objs:
            src = base(objs[0])
        elif OperandType.isScalar(t1) and not OperandType.isDynamic(t1) and objs:
            imm = int(objs[0].getUnsignedValue())
        elif mn == "MOV" and OperandType.isDynamic(t1):
            regs1 = [o for o in objs if isinstance(o, Register)]
            if len(regs1) == 1:
                ld = (base(regs1[0]), sum(int(o.getSignedValue()) for o in objs if isinstance(o, Scalar)))
    pops = 0
    if fm is not None and ptr == 4 and ft.isCall():
        f = _callee(ins, fm)
        if f is not None:
            pops = sum(1 for p in f.getParameters() if p.isStackVariable())
    return Ins(mn, dst, mem, src, imm, writes, bool(ft.isCall()), bool(ft.isJump() or ft.isTerminal()), pops, bits, ld)


def _callee(call: Any, fm: Any) -> Any:
    for flow in call.getFlows():
        f = fm.getFunctionAt(flow)
        if f is None or _in_stubs(call.getProgram(), flow):
            continue
        if f.isThunk():
            f = f.getThunkedFunction(True)
        return f if f is not None and not f.isExternal() else None
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


def _has_code_ref(refman: Any, listing: Any, addr: Any) -> bool:
    return any(listing.getInstructionAt(r.getFromAddress()) is not None for r in refman.getReferencesTo(addr))


def _before(call: Any, ptr: int, fm: Any) -> tuple[list[Ins], list[Any]]:
    """Views of the instructions before ``call``, nearest first, and the instructions themselves."""
    views, raw = [], []
    cur = call.getPrevious()
    while cur is not None and len(views) < CONCAT_WINDOW:
        v = _view(cur, ptr, fm)
        views.append(v)
        raw.append(cur)
        if v.jump or (ptr == 8 and v.call):
            break
        cur = cur.getPrevious()
    return views, raw


def _concat_routines(program: Any, cands: dict[int, Any], ptr: int, out: dict[str, int]) -> set[int]:
    """Entries of the concatenation routines among ``cands`` (entry -> function)."""
    listing = program.getListing()
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    found: set[int] = set()
    for entry, f in cands.items():
        sites = []
        for r in refman.getReferencesTo(f.getEntryPoint()):
            if not r.getReferenceType().isCall():
                continue
            ins = listing.getInstructionAt(r.getFromAddress())
            if ins is None:
                continue
            n, k, _idx = concat_site(_before(ins, ptr, fm)[0], ptr)
            sites.append((n, k))
            if len(sites) >= 200:
                break
        if is_concat(sites):
            found.add(entry)
    out["concat"] = len(found)
    return found


class _Stubs:
    """The stub functions of the concatenation calls. The decompiler takes the pieces of a call to a
    variable-count routine from the callee's signature, and neither an x86 register convention (pieces
    pushed left to right, so they would come out reversed) nor an x64 varargs signature (stack pieces are
    not recovered) can say where they are. So each call gets a reference that overrides its destination
    to a stub function with exactly ``n`` pieces and custom storage; the stubs live in their own block."""

    def __init__(self, program: Any) -> None:
        self.program = program
        self.block: Any = None
        self.by_key: dict[tuple[int, int], Any] = {}
        self.by_vcall: dict[str, Any] = {}
        self.next_slot = 0
        self.failed = False
        blk = program.getMemory().getBlock(STUB_BLOCK)
        if blk is not None:
            self.block = blk
            fm = program.getFunctionManager()
            for fn in fm.getFunctions(blk.getStart(), True):
                if fn.getEntryPoint().compareTo(blk.getEnd()) > 0:
                    break
                tag = str(fn.getComment() or "")
                self.next_slot = max(self.next_slot,
                                     int(fn.getEntryPoint().subtract(blk.getStart())) // STUB_STRIDE + 1)
                if tag.startswith(STUB_TAG):
                    e, n = tag[len(STUB_TAG):].split()
                    if e == "vcall":
                        self.by_vcall[n] = fn.getEntryPoint()
                    else:
                        self.by_key[(int(e, 16), int(n))] = fn.getEntryPoint()
            _rename_stubs(program)      # a routine renamed since the last run: its stubs follow

    def _make_block(self) -> bool:
        import jpype
        from ghidra.util.task import TaskMonitor  # type: ignore
        mem = self.program.getMemory()
        sp = self.program.getAddressFactory().getDefaultAddressSpace()
        size = STUB_SLOTS * STUB_STRIDE
        top = max((int(b.getEnd().getOffset()) for b in mem.getBlocks()), default=0)
        base = (top + 0x1000) & ~0xFFF
        if base + size > int(sp.getMaxAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF:
            return False
        try:
            blk = mem.createInitializedBlock(STUB_BLOCK, sp.getAddress(base), size, jpype.JByte(-61),
                                             TaskMonitor.DUMMY, False)
            blk.setRead(True)
            blk.setWrite(False)
            blk.setExecute(True)
            blk.setComment("airlock: stub functions that give calls of variable-count string "
                           "concatenation routines their exact piece list")
        except Exception:  # noqa: BLE001  overlapping or unsupported: the PRE comment stays the fallback
            return False
        self.block = blk
        return True

    def _grow(self) -> bool:
        """Add ``GROW_SLOTS`` slots behind the block and join them to it (a program of an older run has a block of
        ``STUB_SLOTS``; one stub per (vmt offset, arguments) of a large program needs more)."""
        import jpype
        from ghidra.util.task import TaskMonitor  # type: ignore
        if self.block is None or (int(self.block.getSize()) // STUB_STRIDE) + GROW_SLOTS > MAX_SLOTS:
            return False
        mem = self.program.getMemory()
        old = self.block
        try:
            ext = mem.createInitializedBlock(STUB_BLOCK + "_ext", old.getEnd().add(1), GROW_SLOTS * STUB_STRIDE,
                                             jpype.JByte(-61), TaskMonitor.DUMMY, False)
            ext.setRead(True)
            ext.setWrite(False)
            ext.setExecute(True)
            mem.join(old, ext)
        except Exception:  # noqa: BLE001  something in the way: the stubs stay as they are
            return False
        self.block = mem.getBlock(STUB_BLOCK)
        return self.block is not None

    def _room(self) -> bool:
        """True when the block has a free slot (it is made or grown as needed)."""
        if self.block is None and not self._make_block():
            self.failed = True
            return False
        if self.next_slot >= MAX_SLOTS:
            return False
        if (self.next_slot + 1) * STUB_STRIDE > int(self.block.getSize()) and not self._grow():
            return False
        return True

    def get_vcall(self, key: str, regs: tuple[str, ...], pushes: int) -> Any:
        """Entry of the stub of an indirect call of x86 Pascal code: ``Self`` and the register arguments in
        EAX, EDX, ECX, then ``pushes`` stack arguments (the first one pushed is the deepest), result in EAX,
        the callee pops the stack arguments. Without ``regs`` (Delphi ``stdcall`` and ``safecall``) all
        arguments are on the stack, pushed right to left, so ``Self`` is the top one. None when none can be
        made."""
        from ghidra.program.model.address import AddressSet  # type: ignore
        from ghidra.program.model.data import (PointerDataType, Undefined1DataType, Undefined2DataType,  # type: ignore
                                               Undefined4DataType, VoidDataType)
        from ghidra.program.model.listing import Function, ParameterImpl, VariableStorage  # type: ignore
        from ghidra.program.model.symbol import SourceType  # type: ignore
        from java.util import ArrayList  # type: ignore
        if key in self.by_vcall:
            return self.by_vcall[key]
        if self.failed or len(self.by_vcall) >= MAX_VCALL_STUBS or not self._room():
            return None
        prog = self.program
        at = self.block.getStart().add(self.next_slot * STUB_STRIDE)
        lang = prog.getLanguage()
        stack = prog.getAddressFactory().getStackSpace()
        word = Undefined4DataType.dataType
        try:
            fn = prog.getFunctionManager().createFunction(vcall_name(key), at, AddressSet(at, at),
                                                          SourceType.USER_DEFINED)
            params = ArrayList()
            for i, r in enumerate(regs):
                typ = PointerDataType(VoidDataType.dataType, 4) if i == 0 else (
                    word if r[0] == "E" else Undefined1DataType.dataType if r[1] == "L" else Undefined2DataType.dataType)
                params.add(ParameterImpl("self" if i == 0 else f"a{i}", typ,
                                         VariableStorage(prog, [lang.getRegister(r)]), prog))
            for i in range(pushes):
                at_sp = 4 * i if not regs else 4 * (pushes - 1 - i)
                typ = PointerDataType(VoidDataType.dataType, 4) if not regs and i == 0 else word
                params.add(ParameterImpl("self" if not regs and i == 0 else f"s{i}", typ,
                                         VariableStorage(prog, stack.getAddress(4 + at_sp), 4), prog))
            fn.replaceParameters(params, Function.FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
            fn.setReturnType(word, SourceType.USER_DEFINED)
            fn.setStackPurgeSize(4 * pushes)
            fn.setComment(f"{STUB_TAG}vcall {key}")
        except Exception:  # noqa: BLE001  the call stays as it is
            return None
        self.next_slot += 1
        self.by_vcall[key] = at
        return at

    def get(self, f: Any, n: int, kinds: set[str], ptr: int) -> Any:
        """Entry of the stub for ``n`` pieces of routine ``f``; None when none can be made."""
        from ghidra.program.model.address import AddressSet  # type: ignore
        from ghidra.program.model.data import (IntegerDataType, LongLongDataType, PointerDataType,  # type: ignore
                                               VoidDataType)
        from ghidra.program.model.listing import Function, ParameterImpl, VariableStorage  # type: ignore
        from ghidra.program.model.symbol import SourceType  # type: ignore
        from java.util import ArrayList  # type: ignore
        entry = int(f.getEntryPoint().getOffset())
        key = (entry, n)
        if key in self.by_key:
            return self.by_key[key]
        if self.failed or n > MAX_STUB_PIECES or not self._room():
            return None
        prog = self.program
        at = self.block.getStart().add(self.next_slot * STUB_STRIDE)
        fm = prog.getFunctionManager()
        lang = prog.getLanguage()
        stack = prog.getAddressFactory().getStackSpace()
        piece = _new_type(kinds, ptr)
        count_t = IntegerDataType.dataType if ptr == 4 else LongLongDataType.dataType
        dest_reg, count_reg = ("EAX", "EDX") if ptr == 4 else ("RCX", "RDX")
        try:
            fn = fm.createFunction(stub_name(str(f.getName()), n), at, AddressSet(at, at), SourceType.USER_DEFINED)
            params = ArrayList()
            params.add(ParameterImpl("dest", PointerDataType(piece, ptr),
                                     VariableStorage(prog, [lang.getRegister(dest_reg)]), prog))
            params.add(ParameterImpl("count", count_t, VariableStorage(prog, [lang.getRegister(count_reg)]), prog))
            for i in range(n):
                kind, where = piece_storage(ptr, i, n)
                st = VariableStorage(prog, [lang.getRegister(where)]) if kind == "reg" \
                    else VariableStorage(prog, stack.getAddress(where), ptr)
                params.add(ParameterImpl(f"s{i}", piece, st, prog))
            conv = f.getCallingConventionName()
            if conv:
                try:
                    fn.setCallingConvention(conv)
                except Exception:  # noqa: BLE001  keep the default
                    pass
            fn.replaceParameters(params, Function.FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
            fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
            if ptr == 4:
                fn.setStackPurgeSize(4 * n)
            fn.setComment(f"{STUB_TAG}{entry:x} {n}")
        except Exception:  # noqa: BLE001
            return None
        self.next_slot += 1
        self.by_key[key] = at
        return at


def _override_concat(program: Any, f: Any, kinds: set[str], ptr: int, stubs: _Stubs,
                     out: dict[str, int], lits: dict[int, tuple[str, int, int]]) -> set[int]:
    """Point each call of the concatenation routine ``f`` at its stub; the addresses of the calls done."""
    from ghidra.program.model.symbol import RefType, SourceType  # type: ignore
    listing = program.getListing()
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    done: set[int] = set()
    calls = []
    for r in list(refman.getReferencesTo(f.getEntryPoint())):
        if not r.getReferenceType().isCall():
            continue
        call = listing.getInstructionAt(r.getFromAddress())
        if call is None:
            continue
        views, raw = _before(call, ptr, fm)
        n, k, idx = concat_site(views, ptr)
        if n is None or n != k or n < 1:
            continue
        calls.append((call, n))
        if ptr == 4 and not kinds:      # x86: the callee has no stack parameters; the kinds are in the pushes
            for i in idx:
                for ref in raw[i].getReferencesFrom():
                    lit = lits.get(int(ref.getToAddress().getOffset()))
                    if lit is not None and lit[0] != "s":
                        kinds.add(lit[0])
    for call, n in calls:
        existing = [x for x in call.getReferencesFrom()
                    if x.getReferenceType() == RefType.CALL_OVERRIDE_UNCONDITIONAL]
        if existing and all(_in_stubs(program, x.getToAddress()) for x in existing):
            done.add(int(call.getAddress().getOffset()))
            continue
        if existing:
            continue        # somebody else's override
        at = stubs.get(f, n, kinds, ptr)
        if at is None:
            continue
        ref = refman.addMemoryReference(call.getAddress(), at, RefType.CALL_OVERRIDE_UNCONDITIONAL,
                                        SourceType.USER_DEFINED, 0)
        refman.setPrimary(ref, True)        # the decompiler takes the primary call reference
        done.add(int(call.getAddress().getOffset()))
        out["overrides"] += 1
    return done


def _comment_concat(program: Any, f: Any, lits: dict[int, tuple[str, int, int]], texts: dict[int, str],
                    out: dict[str, int], done: set[int] = frozenset()) -> None:
    """x86: a PRE comment with the pieces at each call of the concatenation routine ``f`` that has no stub
    override (``done``: calls that have; a comment of ours there is removed)."""
    from ghidra.program.model.listing import CommentType  # type: ignore
    listing = program.getListing()
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    for r in refman.getReferencesTo(f.getEntryPoint()):
        if not r.getReferenceType().isCall():
            continue
        call = listing.getInstructionAt(r.getFromAddress())
        if call is None:
            continue
        if int(call.getAddress().getOffset()) in done:
            old = listing.getComment(CommentType.PRE, call.getAddress())
            if old and str(old).startswith(CONCAT_MARK):
                listing.setComment(call.getAddress(), CommentType.PRE, None)
            continue
        views, raw = _before(call, 4, fm)
        n, k, idx = concat_site(views, 4)
        if n is None or k != n:
            continue
        pieces: list[tuple[str, str] | None] = []
        for p in reversed([raw[i] for i in idx]):   # first pushed = first piece
            lit = None
            for ref in p.getReferencesFrom():
                a = int(ref.getToAddress().getOffset())
                if a in lits and lits[a][0] != "s":
                    lit = (lits[a][0], texts[a])
                    break
            pieces.append(lit)
        if not any(pieces):
            continue
        old = listing.getComment(CommentType.PRE, call.getAddress())
        if old and not str(old).startswith(CONCAT_MARK):
            continue
        listing.setComment(call.getAddress(), CommentType.PRE, concat_comment(pieces))
        out["comments"] += 1


def vcall_is_stack(regs: tuple[str, ...], pushes: int) -> bool:
    """True when a Delphi call that pushes arguments loaded no ECX: the ``register`` convention fills EAX, EDX
    and ECX before it pushes, so this is ``stdcall`` or ``safecall`` (all arguments on the stack, ``Self`` last
    pushed), or a register call whose push saves a register (``PUSH EAX`` / ``CALL [EAX + n]``). The stub of
    a stack call has no register parameter, and only a call with the vmt load just before it
    (``MOV EAX, [EAX]``) gets one."""
    return pushes > 0 and not any(r[:2] in ("EC", "CL", "CX") for r in regs)


def _override_vcalls(program: Any, stubs: _Stubs, out: dict[str, int], delphi: bool = False) -> None:
    """x86: point each ``CALL [reg + disp]`` (virtual and interface methods) at a stub with the registers and
    stack slots of the ``register`` convention (Free Pascal and Delphi). Without it the decompiler knows no
    register argument of such a call: a hidden result pointer (``LEA EDX, [local]``) is lost and the local
    reads as the value stored before the call (``x = 0``). With ``delphi`` a call of the stack conventions
    (``vcall_is_stack``) gets a stub with stack parameters only, unless the caller pops them (``cdecl``:
    ``ADD ESP, n`` after the call), which gets none."""
    from ghidra.program.model.symbol import RefType, SourceType  # type: ignore
    listing = program.getListing()
    refman = program.getReferenceManager()
    for call in listing.getInstructions(True):
        ft = call.getFlowType()
        if not ft.isCall() or not ft.isComputed() or _in_stubs(program, call.getAddress()):
            continue
        v = _view(call, 4)
        if v.mem is None or v.mem[0] in ("?", "ESP", "EBP"):
            continue
        views, _raw = _before(call, 4, None)
        regs, pushes, vmt_load = vcall_scan(v, views)
        at = None
        if delphi and vcall_is_stack(regs, pushes):
            regs = ()
            nxt = call.getNext()
            if not vmt_load or (nxt is not None and (nv := _view(nxt, 4)).mn == "ADD" and nv.dst == "ESP"):
                pushes = -1     # no vmt load before the pushes (a register call that saves a register) or cdecl
        if pushes >= 0:
            key = vcall_key(v.mem[1], regs, pushes)
            at = stubs.get_vcall(key, regs, pushes)
        mine = {str(a) for a in stubs.by_vcall.values()}
        old = [x for x in call.getReferencesFrom() if x.getReferenceType() == RefType.CALL_OVERRIDE_UNCONDITIONAL]
        if old and not all(str(x.getToAddress()) in mine for x in old):
            continue            # somebody else's override
        if at is None:
            for x in old:       # a stub of an earlier run that this call no longer gets
                refman.delete(x)
            continue
        if old and all(str(x.getToAddress()) == str(at) for x in old):
            continue            # up to date
        for x in old:           # a stub of an earlier run with other arguments
            refman.delete(x)
        ref = refman.addMemoryReference(call.getAddress(), at, RefType.CALL_OVERRIDE_UNCONDITIONAL,
                                        SourceType.USER_DEFINED, 0)
        refman.setPrimary(ref, True)
        out["vcalls"] += 1


def apply_delphi_strings(program: Any, monitor: Any = None) -> dict[str, int]:
    """Define Delphi string literals and retype the call parameters that receive them. Idempotent; must
    run inside a transaction. Programs without Delphi literals cost a byte scan of their blocks."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    mem = program.getMemory()
    listing = program.getListing()
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    sp = program.getAddressFactory().getDefaultAddressSpace()
    ptr_size = int(sp.getPointerSize())
    lits: dict[int, tuple[str, int, int]] = {}       # chars address -> (kind, byte length, header length)
    texts: dict[int, str] = {}
    bufs: list[tuple[int, bytes]] = []
    for blk in mem.getBlocks():
        if not blk.isInitialized() or blk.isOverlay() or blk.isWrite() and not blk.isExecute() \
                or str(blk.getName()) == STUB_BLOCK:
            continue
        try:
            buf = _block_bytes(blk)
        except Exception:  # noqa: BLE001  unreadable block
            continue
        start = int(blk.getStart().getOffset())
        bufs.append((start, buf))
        for a, kind, nbytes, text in scan_strrec(buf, start):
            lits[a] = (kind, nbytes, 12)
            texts[a] = text
        if ptr_size == 8:
            for a, kind, nbytes, text in scan_strrec64(buf, start):     # Free Pascal
                if a not in lits:
                    lits[a] = (kind, nbytes, 24)
                    texts[a] = text
    out = {"literals": len(lits), "old": 0, "wide": 0, "short": 0, "defined": 0, "cleared": 0, "sites": 0,
           "params": 0, "stack_params": 0, "concat": 0, "varargs": 0, "overrides": 0, "comments": 0, "vcalls": 0}
    modern = len(lits) >= MIN_LITERALS
    if not modern:
        lits.clear()
        texts.clear()
        if not any(delphi_marker(_block_bytes(b)) for b in mem.getBlocks()
                   if b.isInitialized() and not b.isOverlay()):
            return out      # not a Delphi program: change nothing
    # WideString literals (all versions) and, before Delphi 2009, AnsiString literals with the short
    # header; both shapes occur in other data too, so only literals that code points at count
    for start, buf in bufs:
        for a, kind, nbytes, text in scan_old(buf, start):
            if (modern and kind == "a") or a in lits or not _has_code_ref(refman, listing, sp.getAddress(a)):
                continue
            lits[a] = (kind, nbytes, 8 if kind == "a" else 4)
            texts[a] = text
            out["old" if kind == "a" else "wide"] += 1
    out["literals"] = len(lits)
    if not modern and out["old"] < MIN_LITERALS:
        return out          # chance matches: change nothing
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
                lits[start + off] = ("s", len(text) + 1, 0)
                out["short"] += 1
    by_param: dict[tuple[int, int], set[str]] = {}
    funcs: dict[int, Any] = {}
    concat_cands: dict[int, Any] = {}
    not_concat: set[int] = set()
    misses: dict[int, int] = {}
    for a, (kind, nbytes, hdr) in lits.items():
        if monitor is not None and monitor.isCancelled():
            break
        addr = sp.getAddress(a)
        res = _define(program, addr, kind, nbytes, hdr)
        out["defined"] += res > 0
        out["cleared"] += res == 2
        if kind == "s":
            continue        # a ShortString pointer is no C string: the data label is what shows
        for r in refman.getReferencesTo(addr):
            ins = listing.getInstructionAt(r.getFromAddress())
            if ins is None:
                continue
            seq, cur = [], ins
            while cur is not None and len(seq) <= CALL_WINDOW:
                seq.append(_view(cur, ptr_size))
                if seq[-1].call or seq[-1].jump:
                    break
                cur = cur.getNext()
            use = literal_use(seq, ptr_size)
            if use is None:
                continue
            call = ins
            for _ in range(use[2]):
                call = call.getNext()
            f = _callee(call, fm)
            if f is None:
                continue
            entry = int(f.getEntryPoint().getOffset())
            if entry not in concat_cands and entry not in not_concat and (use[0] == "stack" or ptr_size == 8):
                n, k, _idx = concat_site(_before(call, ptr_size, fm)[0], ptr_size)
                if n is not None and n == k:
                    concat_cands[entry] = f
                else:
                    misses[entry] = misses.get(entry, 0) + 1
                    if misses[entry] >= 3:
                        not_concat.add(entry)
            for p in f.getParameters():
                if use[0] == "reg":
                    reg = p.getRegister()
                    hit = reg is not None and str(reg.getBaseRegister().getName()).upper() == use[1]
                else:
                    hit = p.isStackVariable() and int(p.getStackOffset()) == use[1]
                if hit:
                    key = (entry, int(p.getOrdinal()))
                    by_param.setdefault(key, set()).add(kind)
                    funcs[entry] = f
                    out["sites"] += 1
                    break
    concat = _concat_routines(program, concat_cands, ptr_size, out)
    stubs = _Stubs(program)
    for entry in concat:
        f = concat_cands[entry]
        if ptr_size == 8 and f.getSignatureSource() != SourceType.USER_DEFINED and not f.hasVarArgs():
            f.setVarArgs(True)      # calls the stubs do not cover
            out["varargs"] += 1
        kinds: set[str] = set()
        for (e, _o), k in by_param.items():
            if e == entry:
                kinds |= k
        done = _override_concat(program, f, kinds, ptr_size, stubs, out, lits)
        if ptr_size == 4:
            _comment_concat(program, f, lits, texts, out, done)
    for (entry, ordinal), kinds in by_param.items():
        f = funcs[entry]
        if f.getSignatureSource() == SourceType.USER_DEFINED or (ptr_size == 4 and entry in concat):
            continue
        p = f.getParameter(ordinal)
        if p is None or not _retypable(p, ptr_size):
            continue
        try:
            p.setDataType(_new_type(kinds, ptr_size), SourceType.ANALYSIS)
            out["params"] += 1
            out["stack_params"] += bool(p.isStackVariable())
        except Exception:  # noqa: BLE001  one odd signature must not stop the pass
            continue
    if ptr_size == 4:       # Free Pascal or Delphi: the pass got here only for a program with Pascal strings
        fpc = any(fpc_marker(_block_bytes(b)) for b in mem.getBlocks()
                  if b.isInitialized() and not b.isOverlay() and str(b.getName()) != STUB_BLOCK)
        _override_vcalls(program, stubs, out, delphi=not fpc)
        from . import pascalconv
        out.update(pascalconv.apply_register_prototypes(
            program, lambda fn: str(fn.getComment() or "").startswith(STUB_TAG), monitor))
    program.getOptions("airlock").setInt("delphi_strings", VERSION)
    return out
