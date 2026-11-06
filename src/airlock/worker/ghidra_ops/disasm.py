"""disassemble op: the instructions of one function in address order, for `function view=asm`.
With ``raw`` the code at an address that belongs to no function, up to the first RET / unconditional jump.

Result: {"entry", "name", "columns": [...], "rows": [[addr, length, text, note, label, block], ...],
         "total": N, "truncated": bool}
- text: the instruction as Ghidra prints it (mnemonic and operands, names already resolved);
- note: extra resolved references (call targets, strings, globals) not visible in `text`, or "";
- label: the name of a jump target inside the function (LAB_...), or "";
- block: 1 when the instruction starts a basic block (entry, jump target, after a jump,
  return or conditional branch), else 0.
"""

from __future__ import annotations

from typing import Any

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from . import stubs
from .decompile import _resolve_function, check_open
from .session import guarded

COLUMNS = ["addr", "length", "text", "note", "label", "block"]
DEFAULT_MAX = 4000
HARD_MAX = 20000
MAX_NOTES = 2
STR_CHARS = 40


def _string_preview(data: Any) -> str | None:
    try:
        if data is not None and data.hasStringValue():
            v = str(data.getValue())
            v = v.replace("\n", "\n").replace("\r", "\r")
            return '"' + (v if len(v) <= STR_CHARS else v[:STR_CHARS - 3] + "...") + '"'
    except Exception:
        return None
    return None


def _ref_note(program: Any, ref: Any, body: Any) -> str | None:
    """Name for the target of one reference, or None when it adds nothing."""
    rt = ref.getReferenceType()
    if rt.isFallthrough() or ref.isStackReference():
        return None
    to = ref.getToAddress()
    if ref.isExternalReference():
        loc = ref.getExternalLocation() if hasattr(ref, "getExternalLocation") else None
        if loc is not None:
            return f"{loc.getLibraryName()}::{loc.getLabel()}"
        return None
    if to is None or not to.isMemoryAddress():
        return None
    if rt.isJump() and body.contains(to):
        return None  # shown as a label
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(to)
    if f is not None:
        return str(f.getName(True))
    listing = program.getListing()
    data = listing.getDefinedDataAt(to)
    s = _string_preview(data)
    if s is not None:
        return s
    sym = program.getSymbolTable().getPrimarySymbol(to)
    if sym is not None:
        return str(sym.getName(True))
    return None


def disassemble_function(program: Any, func: Any, max_instructions: int) -> dict[str, Any]:
    """Rows for `func`. Caller holds the program's read lock."""
    listing = program.getListing()
    body = func.getBody()
    insns = []
    it = listing.getInstructions(body, True)
    total = 0
    while it.hasNext():
        ins = it.next()
        total += 1
        if len(insns) < max_instructions:
            insns.append(ins)
    rows = _rows(program, insns, body)
    return {"entry": S.addr_int(func.getEntryPoint()), "name": str(func.getName()),
            "columns": COLUMNS, "rows": rows, "total": total, "truncated": total > len(insns)}


class _Span:
    """The addresses of a run of instructions, for the label and note logic that wants a function body."""

    def __init__(self, insns: list[Any]) -> None:
        self.starts = {S.addr_int(i.getAddress()) for i in insns}

    def contains(self, addr: Any) -> bool:
        return S.addr_int(addr) in self.starts


def _rows(program: Any, insns: list[Any], body: Any) -> list[list[Any]]:
    targets: dict[int, str] = {}
    symtab = program.getSymbolTable()
    refs_of: list[Any] = []
    skip = stubs.stub_range(program)
    for ins in insns:
        refs = ins.getReferencesFrom()
        if skip is not None:    # the call overrides to airlock stubs are no program references
            refs = [r for r in refs if not (r.isMemoryReference() and stubs.in_range(skip, S.addr_int(r.getToAddress())))]
        refs_of.append(refs)
        for r in refs:
            rt = r.getReferenceType()
            if rt.isJump() and not rt.isFallthrough() and r.getToAddress() is not None                     and body.contains(r.getToAddress()):
                ta = S.addr_int(r.getToAddress())
                if ta not in targets:
                    sym = symtab.getPrimarySymbol(r.getToAddress())
                    targets[ta] = str(sym.getName()) if sym is not None else f"LAB_{ta:08x}"
    rows: list[list[Any]] = []
    starts_block = True
    for ins, refs in zip(insns, refs_of):
        a = S.addr_int(ins.getAddress())
        text = str(ins.toString())
        notes: list[str] = []
        for r in refs:
            n = _ref_note(program, r, body)
            if n and n not in text and n not in notes:
                notes.append(n)
            if len(notes) >= MAX_NOTES:
                break
        label = targets.get(a, "")
        for r in refs:  # a jump inside the function reads `JNZ LAB_x`, not `JNZ 0x...`
            ta = S.addr_int(r.getToAddress()) if r.getToAddress() is not None else None
            if ta in targets and r.getReferenceType().isJump():
                text = text.replace(f"0x{ta:x}", targets[ta])
        ft = ins.getFlowType()
        block = 1 if (starts_block or label) else 0
        starts_block = bool(ft.isJump() or ft.isTerminal() or ft.isConditional())
        rows.append([a, int(ins.getLength()), text, ", ".join(notes),
                     label, block])
    return rows


def _raw_run(program: Any, start: Any, max_instructions: int, load: Any = None) -> tuple[list[Any], bool]:
    """Instructions from ``start`` to the first RET / unconditional jump (included). Stops before a function
    entry, a missing instruction or the airlock stub block. (instructions, ended) - ended is False at the cap."""
    listing = program.getListing()
    fm = program.getFunctionManager()
    skip = stubs.stub_range(program)
    out: list[Any] = []
    addr = start
    while len(out) < max_instructions:
        ins = listing.getInstructionAt(addr)
        if ins is None and load is not None:
            load(addr)
            ins = listing.getInstructionAt(addr)
        if ins is None or stubs.in_range(skip, S.addr_int(addr)):
            return out, True
        if out and fm.getFunctionAt(addr) is not None:
            return out, True
        out.append(ins)
        ft = ins.getFlowType()
        if ft.isTerminal() or (ft.isJump() and not ft.isConditional()):
            return out, True
        addr = ins.getMaxAddress().add(1)
    return out, False


def disassemble_range(program: Any, start: Any, max_instructions: int, load: Any = None) -> dict[str, Any]:
    """Rows for the code at ``start`` that belongs to no function (see ``_raw_run``)."""
    insns, ended = _raw_run(program, start, max_instructions, load)
    if not insns:
        raise WorkerError("no_code", f"no instruction at {start}")
    rows = _rows(program, insns, _Span(insns))
    return {"entry": S.addr_int(start), "name": "", "columns": COLUMNS, "rows": rows,
            "total": len(rows), "truncated": not ended}


@op("disassemble")
@guarded
def disassemble(args: dict[str, Any]) -> dict[str, Any]:
    """disassemble(program, entry, max_instructions=4000): instructions of the function at or
    containing `entry`, in address order, with resolved references and basic-block marks."""
    e = S.ready_entry(args.get("program"))
    try:
        mx = int(args.get("max_instructions") or DEFAULT_MAX)
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"max_instructions must be an integer ({ex})") from ex
    mx = max(1, min(mx, HARD_MAX))
    if args.get("raw"):
        return _disassemble_raw(e, args.get("entry"), mx)
    with e.lock.read():
        check_open(e)
        func = _resolve_function(e.program, args.get("entry"))
        if func.isExternal():
            raise WorkerError("no_function", f"'{func.getName()}' is an external function")
        return disassemble_function(e.program, func, mx)


def _disassemble_raw(e: Any, entry: Any, mx: int) -> dict[str, Any]:
    """Code that belongs to no function: from ``entry`` to the first RET / unconditional jump. Instructions that
    Ghidra already has are read under the read lock. When there are none, the bytes are disassembled inside a
    transaction that is rolled back, so the program and the project file stay as they are."""
    try:
        off = int(entry, 0) if isinstance(entry, str) else int(entry)
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"entry must be an integer address ({ex})") from ex
    with e.lock.read():
        check_open(e)
        start = e.program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        if stubs.in_stubs(e.program, start):
            raise WorkerError("bad_args", f"{start} is not in the program's memory")
        if e.program.getListing().getInstructionAt(start) is not None:
            return disassemble_range(e.program, start, mx)
    from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    with e.fg, e.lock:
        check_open(e)
        program = e.program
        start = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        mem = program.getMemory()
        block = mem.getBlock(start)
        if block is None or not block.isExecute() or not block.isInitialized():
            raise WorkerError("no_code", f"{start} is not in executable memory")
        monitor = TaskMonitorAdapter()
        tx = program.startTransaction("airlock disassembly preview")
        try:
            def load(a: Any) -> None:
                DisassembleCommand(a, None, True).applyTo(program, monitor)
            return disassemble_range(program, start, mx, load)
        finally:
            program.endTransaction(tx, False)       # rolled back: nothing is written
