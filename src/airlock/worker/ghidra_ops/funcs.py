"""create_functions: make Ghidra functions at addresses that static tables prove are code.

MFC message map handlers and vtable slot targets are found by the server from the PE bytes. Ghidra's
auto-analysis does not always create a function there (the bytes were never reached by flow). This
op disassembles and creates them, one transaction under the write lock, then saves.

Per address (ascending), the outcome is one of
- created: a function now starts there (counted in ``created``);
- exists: a function already starts there;
- inside_function: the address lies in the body of another function (never split);
- inside_instruction: the address is in the middle of an instruction;
- not_executable: no initialised executable memory block at the address;
- defined_data: defined data (not 'undefined') covers the address and does not start at it;
- no_code: disassembly produced no instruction at the address;
- data: defined data (a string, a pointer) starts at the address and nothing jumps or calls there (kept; skipped
  unless ``known_code`` is set);
- interior (reported as created): the address lies in the flow of an earlier call target; the function was
  created there instead (``resolved`` maps address -> entry);
- failed: Ghidra refused to create the function. A trial disassembly that makes no function is undone.
``failed`` counts failed, no_code and error:*; ``skipped`` the other outcomes; ``reasons`` counts each.
"""

from __future__ import annotations

import sys
import time
from typing import Any

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import fixups, stubs
from .annotate import _address, _write
from .session import guarded

MAX_ADDRESSES = 20000
SAMPLE = 5          # addresses kept per reason


def _int_list(value: Any) -> list[int]:
    if not isinstance(value, list) or not value:
        raise WorkerError("bad_args", "addresses must be a non-empty list of integers")
    if len(value) > MAX_ADDRESSES:
        raise WorkerError("bad_args", f"at most {MAX_ADDRESSES} addresses per call")
    try:
        return sorted({int(v, 0) if isinstance(v, str) else int(v) for v in value})
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"addresses must be integers ({ex})") from ex


def _refuse_stub(program: Any, addr: Any) -> None:
    """The airlock stub block is no program memory (same answer as ``set_comment``)."""
    if stubs.in_stubs(program, addr):
        raise WorkerError("bad_args", f"{addr} is not in the program's memory")


BACK_REACH = 0x4000   # how far before an address a call target is searched (interior addresses)
BACK_TRIES = 3        # call targets tried, nearest first


def _flow_ref(program: Any, addr: Any) -> bool:
    """True when a call or jump reference points at ``addr`` (a data reference alone does not make it code)."""
    for r in program.getReferenceManager().getReferencesTo(addr):
        t = r.getReferenceType()
        if t.isCall() or t.isJump():
            return True
    return False


def _call_ref(program: Any, addr: Any) -> bool:
    """True when a call reference points at ``addr`` (a routine entry; a jump may also target the inside)."""
    return any(r.getReferenceType().isCall() for r in program.getReferenceManager().getReferencesTo(addr))


def _undo(program: Any, aset: Any) -> None:
    """Remove what a trial disassembly added: its instructions and the references from them."""
    if aset is None:
        return
    listing, rm = program.getListing(), program.getReferenceManager()
    for rng in aset:
        rm.removeAllReferencesFrom(rng.getMinAddress(), rng.getMaxAddress())
        listing.clearCodeUnits(rng.getMinAddress(), rng.getMaxAddress(), False)


def _make(program: Any, addr: Any, monitor: Any) -> str:
    """Disassemble at ``addr`` and create the function; the trial is undone unless a function results.
    Returns 'created', 'no_code' or 'failed'."""
    from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
    from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore

    fm, listing = program.getFunctionManager(), program.getListing()
    aset = None
    if listing.getInstructionAt(addr) is None:
        dis = DisassembleCommand(addr, None, True)
        dis.applyTo(program, monitor)
        aset = dis.getDisassembledAddressSet()
        if listing.getInstructionAt(addr) is None:
            _undo(program, aset)
            return "no_code"
    cmd = CreateFunctionCmd(addr, False)
    if not cmd.applyTo(program, monitor) or fm.getFunctionAt(addr) is None:
        _undo(program, aset)
        return "failed"
    return "created"


def _outer(program: Any, addr: Any, monitor: Any) -> Any:
    """The entry of a routine that reaches ``addr`` by flow, or None. Candidates are the nearest call targets
    before ``addr`` that lie in no function; a function created for a candidate that does not contain ``addr``
    is removed again."""
    fm, mem = program.getFunctionManager(), program.getMemory()
    block = mem.getBlock(addr)
    lo = max(block.getStart().getOffset(), addr.getOffset() - BACK_REACH)
    if lo >= addr.getOffset():
        return None
    rm = program.getReferenceManager()
    from ghidra.program.model.address import AddressSet  # type: ignore

    rng = AddressSet(addr.getNewAddress(lo), addr.subtract(1))
    tried = 0
    dests = sorted(rm.getReferenceDestinationIterator(rng, True), key=lambda x: x.getOffset(), reverse=True)
    for d in dests:       # nearest first
        if fm.getFunctionContaining(d) is not None:
            return None             # a routine lies between: the address is not in the flow of an earlier one
        if not _call_ref(program, d):
            continue
        tried += 1
        if _make(program, d, monitor) == "created":
            f = fm.getFunctionAt(d)
            if f is not None and f.getBody().contains(addr):
                return d
            if f is not None:
                aset = f.getBody()
                fm.removeFunction(d)
                _undo(program, aset)
        if tried >= BACK_TRIES:
            break
    return None


def _one(program: Any, addr: Any, monitor: Any, known_code: bool = False, extra: dict[str, Any] | None = None) -> str:
    """Create the function at ``addr``; returns 'created' or the reason it was not.

    ``known_code``: the caller proved the address is code (static tables); otherwise defined data that starts
    at the address stays (reason ``data``), and an address inside the flow of an earlier call target gets
    that routine instead (counted as created; ``extra['resolved']`` maps the address to the routine entry).
    A trial that makes no function is undone."""
    fm, listing, mem = program.getFunctionManager(), program.getListing(), program.getMemory()
    extra = extra if extra is not None else {}
    block = mem.getBlock(addr)
    if block is None or not block.isExecute() or not block.isInitialized():
        return "not_executable"
    f = fm.getFunctionContaining(addr)
    if f is not None:
        return "exists" if f.getEntryPoint().equals(addr) else "inside_function"
    ins = listing.getInstructionContaining(addr)
    if ins is not None and not ins.getMinAddress().equals(addr):
        return "inside_instruction"
    if ins is None:
        data = listing.getDataContaining(addr)
        if data is not None and data.isDefined():
            if not data.getMinAddress().equals(addr):
                return "defined_data"
            if not known_code and not _flow_ref(program, addr):
                extra.setdefault("data", {})[int(addr.getOffset())] = (
                    f"{data.getDataType().getName()} {data.getDefaultValueRepresentation()}")
                return "data"
            listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), False)
    if not known_code and not _call_ref(program, addr):
        outer = _outer(program, addr, monitor)
        if outer is not None:
            extra.setdefault("resolved", {})[int(addr.getOffset())] = int(outer.getOffset())
            return "created"
    return _make(program, addr, monitor)


def _scalar_refs(program: Any, made: list[Any], extra: dict[str, Any], monitor: Any) -> None:
    """Data references from the operands of the new code (Ghidra's analysis ran before these functions existed):
    a string literal that only a new function loads must show that function. Failure is not fatal."""
    if not made:
        return
    try:
        from ghidra.app.plugin.core.analysis import ScalarOperandAnalyzer  # type: ignore
        from ghidra.app.util.importer import MessageLog  # type: ignore
        from ghidra.program.model.address import AddressSet  # type: ignore

        fm, body = program.getFunctionManager(), AddressSet()
        for a in made:
            outer = (extra.get("resolved") or {}).get(int(a.getOffset()))
            f = fm.getFunctionContaining(a if outer is None else a.getNewAddress(outer))
            if f is not None:
                body.add(f.getBody())
        ScalarOperandAnalyzer().added(program, body, monitor, MessageLog())
    except Exception as ex:  # noqa: BLE001
        print(f"create_functions: operand references not added ({type(ex).__name__}: {ex})", file=sys.stderr)


@op("create_functions")
@guarded
def create_functions(args: dict[str, Any]) -> dict[str, Any]:
    """create_functions(program, addresses, space=None, conventions=True, known_code=False): disassemble and create a function at each
    address that is code but belongs to no function. Returns created, skipped, failed, reasons
    (count per outcome), sample (a few addresses per failing reason) and the conventions set on
    the new functions."""
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    addresses = _int_list(args.get("addresses"))
    space = args.get("space")
    t0 = time.monotonic()
    monitor = TaskMonitorAdapter()
    stats: dict[str, Any] = {}
    extra: dict[str, Any] = {}

    def body(e: Any, program: Any) -> dict[str, Any]:
        reasons: dict[str, int] = {}
        sample: dict[str, list[int]] = {}
        known = bool(args.get("known_code"))
        made: list[Any] = []
        for a in addresses:
            addr = _address(program, space, a)
            _refuse_stub(program, addr)
            try:
                r = _one(program, addr, monitor, known, extra)
            except Exception as ex:  # noqa: BLE001  one address must not stop the others
                r = f"error:{type(ex).__name__}"
            reasons[r] = reasons.get(r, 0) + 1
            if r == "created":
                made.append(addr)
            if r not in ("created", "exists") and len(sample.setdefault(r, [])) < SAMPLE:
                sample[r].append(a)
        stats["reasons"], stats["sample"] = reasons, sample
        _scalar_refs(program, made, extra, monitor)
        if reasons.get("created") and args.get("conventions", True):
            stats["conventions"] = fixups.apply_conventions(program, monitor, relabel_fastcall=True)
        return {}

    _write(args, "create functions", body)
    reasons = stats["reasons"]
    created = reasons.get("created", 0)
    failed = sum(n for k, n in reasons.items() if k in ("failed", "no_code") or k.startswith("error:"))
    return {"program": args.get("program"), "requested": len(addresses), "created": created,
            "skipped": len(addresses) - created - failed, "failed": failed, "reasons": reasons,
            "sample": {k: [hex(x) for x in v] for k, v in stats["sample"].items() if k != "exists"},
            "conventions": stats.get("conventions", {}),
            "resolved": {hex(k): hex(v) for k, v in (extra.get("resolved") or {}).items()},
            "data": {hex(k): v for k, v in (extra.get("data") or {}).items()}, "secs": round(time.monotonic() - t0, 1)}
