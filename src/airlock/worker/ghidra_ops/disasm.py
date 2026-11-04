"""disassemble op: the instructions of one function in address order, for `function view=asm`.

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
    targets: dict[int, str] = {}
    symtab = program.getSymbolTable()
    refs_of: list[Any] = []
    for ins in insns:
        refs = ins.getReferencesFrom()
        refs_of.append(refs)
        for r in refs:
            rt = r.getReferenceType()
            if rt.isJump() and not rt.isFallthrough() and r.getToAddress() is not None \
                    and body.contains(r.getToAddress()):
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
    return {"entry": S.addr_int(func.getEntryPoint()), "name": str(func.getName()),
            "columns": COLUMNS, "rows": rows, "total": total, "truncated": total > len(insns)}


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
    with e.lock.read():
        check_open(e)
        func = _resolve_function(e.program, args.get("entry"))
        if func.isExternal():
            raise WorkerError("no_function", f"'{func.getName()}' is an external function")
        return disassemble_function(e.program, func, mx)
