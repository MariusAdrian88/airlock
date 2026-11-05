"""warp_blocks op: basic blocks and per-instruction masking facts for the WARP function GUID.

The server (server/warp.py) applies the WARP rules; this op only reports what Ghidra knows.

Result: {"regions": [[lo, hi], ...], "fns": [[entry, [[start, hexbytes, [len, flags, ...]], ...]], ...]}
- regions: initialised memory blocks (the relocatable regions of WARP; the PE header block is left out);
- one entry per requested function, blocks by Ghidra's simple block model (a call does not end a block);
- per block the raw bytes (hex) and, per instruction, its length and a flags bit set:
  1 an operand or reference holds a value inside a region (plus or minus 0x10000), 2 call, 4 unconditional jump,
  8 conditional jump, 16 return, 32 nop-like (nop, mov r,r with the same register, lea r,[r]),
  64 jump leaves the function (or is indirect).
"""

from __future__ import annotations

from typing import Any

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from .annotate import _address
from .decompile import check_open
from .session import guarded

MAX_FUNCTIONS = 2000
THRESHOLD = 0x10000
F_CONST, F_CALL, F_JMP, F_JCC, F_RET, F_NOP, F_OUT = 1, 2, 4, 8, 16, 32, 64


def _regions(program: Any) -> list[tuple[int, int]]:
    out = []
    for b in program.getMemory().getBlocks():
        if not b.isInitialized() or b.isOverlay() or str(b.getName()).lower() == "headers":
            continue
        out.append((int(b.getStart().getOffset()), int(b.getEnd().getOffset()) + 1))
    return out


def _in_region(regions: list[tuple[int, int]], v: int) -> bool:
    for lo, hi in regions:
        if lo <= v < hi:
            return True
        if v > hi and v > THRESHOLD and v <= hi + THRESHOLD:
            return True
        if v < lo and v > THRESHOLD and v >= lo - THRESHOLD:
            return True
    return False


def _is_nop(ins: Any) -> bool:
    mn = str(ins.getMnemonicString()).upper()
    if mn == "NOP":
        return True
    if mn in ("MOV", "XCHG") and ins.getNumOperands() == 2:
        a, b = ins.getOpObjects(0), ins.getOpObjects(1)
        if len(a) == 1 and len(b) == 1 and a[0].getClass().getSimpleName() == "Register" \
                and b[0].getClass().getSimpleName() == "Register" and str(a[0]) == str(b[0]):
            return True
    return False


def _flags(ins: Any, regions: list[tuple[int, int]], body: Any) -> int:
    ft = ins.getFlowType()
    f = 0
    if ft.isCall():
        f |= F_CALL
    elif ft.isTerminal():
        f |= F_RET
    elif ft.isJump():
        if ft.isConditional():
            f |= F_JCC
        else:
            f |= F_JMP
            tgt = ins.getFlows()
            if ft.isComputed() or len(tgt) != 1 or not body.contains(tgt[0]):
                f |= F_OUT
    if _is_nop(ins):
        f |= F_NOP
    hit = False
    for i in range(ins.getNumOperands()):
        for o in ins.getOpObjects(i):
            n = o.getClass().getSimpleName()
            if n == "Scalar":
                hit = hit or _in_region(regions, int(o.getUnsignedValue()))
            elif n == "GenericAddress" or hasattr(o, "getOffset") and n.endswith("Address"):
                hit = hit or _in_region(regions, int(o.getOffset()))
    if not hit:
        for r in ins.getReferencesFrom():
            to = r.getToAddress()
            if to is not None and to.isMemoryAddress() and _in_region(regions, int(to.getOffset())):
                hit = True
                break
    return f | (F_CONST if hit else 0)


def function_blocks(program: Any, func: Any, regions: list[tuple[int, int]], model: Any, monitor: Any) -> list[Any]:
    listing = program.getListing()
    body = func.getBody()
    out = []
    it = model.getCodeBlocksContaining(body, monitor)
    while it.hasNext():
        cb = it.next()
        data = bytearray()
        meta: list[int] = []
        ii = listing.getInstructions(cb, True)
        while ii.hasNext():
            ins = ii.next()
            data += bytes(b & 0xFF for b in ins.getBytes())
            meta += [int(ins.getLength()), _flags(ins, regions, body)]
        out.append([int(cb.getMinAddress().getOffset()), data.hex(), meta])
    out.sort(key=lambda b: b[0])
    return out


@op("warp_blocks")
@guarded
def warp_blocks(args: dict[str, Any]) -> dict[str, Any]:
    """warp_blocks(program, entries, space=None): basic blocks with masking facts for the functions at `entries`
    (at most 2000 per call); unknown entries are skipped."""
    from ghidra.program.model.block import BasicBlockModel  # type: ignore
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    entries = args.get("entries")
    if not isinstance(entries, list) or not entries:
        raise WorkerError("bad_args", "entries must be a non-empty list of integers")
    if len(entries) > MAX_FUNCTIONS:
        raise WorkerError("bad_args", f"at most {MAX_FUNCTIONS} entries per call")
    e = S.ready_entry(args.get("program"))
    monitor = TaskMonitorAdapter()
    with e.lock.read():
        check_open(e)
        program = e.program
        fm = program.getFunctionManager()
        regions = _regions(program)
        model = BasicBlockModel(program)
        fns = []
        for off in entries:
            func = fm.getFunctionAt(_address(program, args.get("space"), off))
            if func is None or func.isExternal() or func.isThunk():
                continue
            fns.append([int(func.getEntryPoint().getOffset()), function_blocks(program, func, regions, model, monitor)])
    return {"regions": [list(r) for r in regions], "fns": fns}
