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
- failed: Ghidra refused to create the function.
``failed`` counts failed, no_code and error:*; ``skipped`` the other outcomes; ``reasons`` counts each.
"""

from __future__ import annotations

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


def _one(program: Any, addr: Any, monitor: Any) -> str:
    """Create the function at ``addr``; returns 'created' or the reason it was not."""
    from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
    from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore

    fm, listing, mem = program.getFunctionManager(), program.getListing(), program.getMemory()
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
            listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), False)
        DisassembleCommand(addr, None, True).applyTo(program, monitor)
        if listing.getInstructionAt(addr) is None:
            return "no_code"
    cmd = CreateFunctionCmd(addr, False)
    if not cmd.applyTo(program, monitor) or fm.getFunctionAt(addr) is None:
        return "failed"
    return "created"


@op("create_functions")
@guarded
def create_functions(args: dict[str, Any]) -> dict[str, Any]:
    """create_functions(program, addresses, space=None, conventions=True): disassemble and create a function at each
    address that is code but belongs to no function. Returns created, skipped, failed, reasons
    (count per outcome), sample (a few addresses per failing reason) and the conventions set on
    the new functions."""
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    addresses = _int_list(args.get("addresses"))
    space = args.get("space")
    t0 = time.monotonic()
    monitor = TaskMonitorAdapter()
    stats: dict[str, Any] = {}

    def body(e: Any, program: Any) -> dict[str, Any]:
        reasons: dict[str, int] = {}
        sample: dict[str, list[int]] = {}
        for a in addresses:
            addr = _address(program, space, a)
            _refuse_stub(program, addr)
            try:
                r = _one(program, addr, monitor)
            except Exception as ex:  # noqa: BLE001  one address must not stop the others
                r = f"error:{type(ex).__name__}"
            reasons[r] = reasons.get(r, 0) + 1
            if r not in ("created", "exists") and len(sample.setdefault(r, [])) < SAMPLE:
                sample[r].append(a)
        stats["reasons"], stats["sample"] = reasons, sample
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
            "conventions": stats.get("conventions", {}), "secs": round(time.monotonic() - t0, 1)}
