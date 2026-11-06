"""Post-analysis call fixups for compiler prolog helpers Function ID does not name.

32-bit MSVC code with a statically linked CRT/MFC starts most functions with a call to
a tiny helper that builds the SEH/EH frame (`__EH_prolog`). Ghidra's x86 windows cspec
has a call-fixup (an inline p-code body) for that helper, but only when the helper is
named and `Function.setCallFixup` was set. Function ID names the larger helpers
(`__SEH_prolog`, `__EH_prolog3`, ...) and sets their fixup, but not this 30-byte one, so
every caller decompiles with `unaff_EBP + -0x18` frame accesses. This module finds such
helpers by their exact entry bytes, names them and sets the fixup.

`classify_helper` is pure (no Ghidra) so it can be unit-tested.
"""

from __future__ import annotations

import re
from typing import Any

from .stubs import STUB_TAG


def _is_stub(f: Any) -> bool:
    """An airlock stub function (delphistr), not program content."""
    return str(f.getComment() or "").startswith(STUB_TAG)


# name, call-fixup name (x86win.cspec), exact entry bytes of the helper
HELPERS: tuple[tuple[str, str, bytes], ...] = (
    ("__EH_prolog", "EH_prolog", bytes.fromhex(
        "6aff"              # push -1
        "50"                # push eax
        "64a100000000"      # mov eax, fs:[0]
        "50"                # push eax
        "8b44240c"          # mov eax, [esp+0xc]
        "64892500000000"    # mov fs:[0], esp
        "896c240c"          # mov [esp+0xc], ebp
        "8d6c240c"          # lea ebp, [esp+0xc]
        "50"                # push eax
        "c3")),             # ret
)
MAX_HELPER_SIZE = max(len(h[2]) for h in HELPERS)


def classify_helper(code: bytes) -> tuple[str, str] | None:
    """(name, fixup) when `code` (the function's bytes) is exactly a known helper."""
    for name, fixup, pattern in HELPERS:
        if code == pattern:
            return name, fixup
    return None


def apply_call_fixups(program: Any) -> int:
    """Name known prolog helpers and set their call fixup. Returns the number changed.

    Must run inside a transaction on `program`. Only functions no larger than the
    biggest pattern are read, so the scan is cheap.
    """
    import jpype
    from ghidra.program.model.symbol import SourceType  # type: ignore

    mem = program.getMemory()
    changed = 0
    for f in program.getFunctionManager().getFunctions(True):
        if f.isExternal() or _is_stub(f) or f.isThunk() or int(f.getBody().getNumAddresses()) > MAX_HELPER_SIZE:
            continue
        size = int(f.getBody().getNumAddresses())
        buf = jpype.JArray(jpype.JByte)(size)
        try:
            mem.getBytes(f.getEntryPoint(), buf)
        except Exception:  # uninitialised or unreadable
            continue
        hit = classify_helper(bytes(memoryview(buf).cast("B")))
        if hit is None:
            continue
        name, fixup = hit
        if f.getSymbol().getSource() == SourceType.DEFAULT:
            try:
                f.setName(name, SourceType.ANALYSIS)
            except Exception:  # name clash: keep the default name, the fixup still works
                pass
        if f.getCallFixup() != fixup:
            f.setCallFixup(fixup)
            changed += 1
    return changed


# -- calling convention heuristic (32-bit x86) ----------------------------------------
#
# Pure part: instructions are `(mnemonic, operands)` tuples with upper-case mnemonics and
# operand text as Ghidra prints it ("ECX", "dword ptr [ESI + 0x4]", "0x8"). A direct CALL
# carries the callee's name as its only operand.

Ins = tuple[str, tuple[str, ...]]
# one direct call site: up to SITE_WINDOW instructions before the CALL (oldest first) and the
# instruction right after it (None when unknown)
Site = tuple[tuple[Ins, ...], "Ins | None"]

SCAN_LIMIT = 48            # instructions of the entry path examined for register reads
SITE_WINDOW = 6            # instructions before a CALL that may set ECX/EDX
MAX_SITES = 16             # call sites examined per function
THISCALL, FASTCALL, STDCALL, CDECL = "__thiscall", "__fastcall", "__stdcall", "__cdecl"
UNSET_CONVENTIONS = ("unknown", "default", "")

_REG_RE = {
    "ECX": re.compile(r"\b(ECX|CX|CL|CH)\b", re.I),
    "EDX": re.compile(r"\b(EDX|DX|DL|DH)\b", re.I),
}
_REG_EXACT = {"ECX": {"ECX", "CX", "CL", "CH"}, "EDX": {"EDX", "DX", "DL", "DH"}}
_WRITE_ONLY = {"MOV", "LEA", "MOVZX", "MOVSX", "POP"}
_ENDS_PATH = {"RET", "RETN", "JMP", "INT3", "UD2", "HLT"}
_PROLOG_HELPERS = ("_EH_prolog", "_SEH_prolog")   # keep ECX/EDX, so the scan goes on


def _is_reg(text: str, reg: str) -> bool:
    return text.strip().upper() in _REG_EXACT[reg]


def _transparent(ops: tuple[str, ...]) -> bool:
    return bool(ops) and any(h in ops[0] for h in _PROLOG_HELPERS)


def regs_read_first(entry: "list[Ins] | tuple[Ins, ...]") -> tuple[bool, bool]:
    """(ECX, EDX) read before being written on the straight-line entry path.

    The scan stops at the first CALL (a call clobbers both) unless it targets an
    `_EH_prolog`/`_SEH_prolog` helper, which keeps them; it also stops at RET/JMP.
    `PUSH ECX` alone does not count (compilers use it to reserve a stack slot)."""
    state: dict[str, bool | None] = {"ECX": None, "EDX": None}  # None untouched, True read first
    for mn, ops in list(entry)[:SCAN_LIMIT]:
        if mn == "CALL":
            if _transparent(ops):
                continue
            break
        if mn in _ENDS_PATH:
            break
        if mn == "PUSH":
            continue
        for reg in ("ECX", "EDX"):
            if state[reg] is not None:
                continue
            dst_is_reg = bool(ops) and _is_reg(ops[0], reg)
            zeroing = mn in ("XOR", "SUB") and len(ops) == 2 and ops[0].upper() == ops[1].upper()
            writes = dst_is_reg and (mn in _WRITE_ONLY or zeroing)
            if zeroing and dst_is_reg:
                state[reg] = False
                continue
            reads_src = any(_REG_RE[reg].search(o) for o in ops[1:])
            reads_dst = bool(ops) and bool(_REG_RE[reg].search(ops[0])) and not writes
            if reads_src or reads_dst:
                state[reg] = True
            elif writes:
                state[reg] = False
    return bool(state["ECX"]), bool(state["EDX"])


def site_sets(before: tuple[Ins, ...], reg: str) -> bool:
    """Does one of the instructions before a CALL load `reg` (MOV/LEA/POP/XOR reg, x)?"""
    for mn, ops in before:
        if (mn in _WRITE_ONLY or mn == "XOR") and ops and _is_reg(ops[0], reg):
            return True
    return False


def site_cleanup(after: "Ins | None") -> int:
    """Bytes the caller pops right after the call (`ADD ESP, n`, `POP reg`), else 0."""
    if after is None:
        return 0
    mn, ops = after
    if mn == "ADD" and len(ops) == 2 and ops[0].upper() == "ESP":
        try:
            return int(ops[1], 0)
        except ValueError:
            return 0
    if mn == "POP" and ops and ops[0].upper() in ("ECX", "EBX", "ESI", "EDI"):
        return 4
    return 0


def classify_convention(entry: "list[Ins] | tuple[Ins, ...]", ret_sizes: list[int],
                        sites: "list[Site]") -> str | None:
    """Calling convention of a 32-bit x86 function from its instructions, or None when the
    evidence is weak. `ret_sizes` holds the distinct immediates of the RETs (0: plain RET)."""
    ecx, edx = regs_read_first(entry)
    n = len(sites)
    if len(set(ret_sizes)) > 1:
        return None
    ret_n = ret_sizes[0] if ret_sizes else None
    set_ecx = sum(site_sets(b, "ECX") for b, _a in sites)
    set_edx = sum(site_sets(b, "EDX") for b, _a in sites)
    if ecx:
        if n and set_ecx * 2 < n:
            return None                       # callers do not pass ECX: not a this pointer
        if edx and (not n or set_edx * 2 >= n):
            return FASTCALL
        return THISCALL
    if ret_n:
        return STDCALL
    if ret_n == 0 and n and sum(1 for _b, a in sites if site_cleanup(a) > 0) * 2 >= n:
        return CDECL
    return None


def _ins_tuple(ins: Any, fm: Any) -> Ins:
    mn = str(ins.getMnemonicString()).upper()
    if mn == "CALL":
        flows = ins.getFlows()
        f = fm.getFunctionAt(flows[0]) if len(flows) else None
        return mn, ((str(f.getName()) if f is not None else ""),)
    return mn, tuple(str(ins.getDefaultOperandRepresentation(i)) for i in range(ins.getNumOperands()))


def _entry_path(listing: Any, fm: Any, entry: Any) -> list[Ins]:
    out: list[Ins] = []
    ins = listing.getInstructionAt(entry)
    while ins is not None and len(out) < SCAN_LIMIT:
        t = _ins_tuple(ins, fm)
        out.append(t)
        if t[0] in _ENDS_PATH or (t[0] == "CALL" and not _transparent(t[1])):
            break
        ins = ins.getNext()
    return out


def _ret_sizes(listing: Any, body: Any) -> list[int]:
    sizes: set[int] = set()
    for ins in listing.getInstructions(body, True):
        if str(ins.getMnemonicString()).upper() in ("RET", "RETN"):
            try:
                sizes.add(int(str(ins.getDefaultOperandRepresentation(0)), 0)
                          if ins.getNumOperands() else 0)
            except ValueError:
                sizes.add(0)
    return sorted(sizes)


def _call_sites(program: Any, listing: Any, fm: Any, entry: Any) -> list[Site]:
    sites: list[Site] = []
    for ref in program.getReferenceManager().getReferencesTo(entry):
        if not ref.getReferenceType().isCall():
            continue
        call = listing.getInstructionAt(ref.getFromAddress())
        if call is None:
            continue
        before: list[Ins] = []
        p = call.getPrevious()
        while p is not None and len(before) < SITE_WINDOW:
            t = _ins_tuple(p, fm)
            if t[0] in _ENDS_PATH or t[0] == "CALL":
                break
            before.append(t)
            p = p.getPrevious()
        nxt = call.getNext()
        sites.append((tuple(reversed(before)), _ins_tuple(nxt, fm) if nxt is not None else None))
        if len(sites) >= MAX_SITES:
            break
    return sites


def _relabel_thiscall(program: Any, f: Any) -> None:
    """__fastcall -> __thiscall for a function whose only register parameter is ECX: drop that
    parameter (the new `this` replaces it), keep the others with their types."""
    from ghidra.program.model.listing import Function, ParameterImpl  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    params = list(f.getParameters())
    if params and params[0].isRegisterVariable() and str(params[0].getRegister().getName()) == "ECX":
        params = params[1:]
    rest = [ParameterImpl(None, p.getDataType(), program) for p in params]
    f.updateFunction(THISCALL, None, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                     SourceType.ANALYSIS, *rest)


def apply_conventions(program: Any, monitor: Any = None,
                      relabel_fastcall: bool = False) -> dict[str, int]:
    """Set the calling convention of 32-bit x86 functions that have none (unknown or default,
    signature not user-defined) from their instructions. Must run inside a transaction.
    With `relabel_fastcall`, functions that Decompiler Parameter ID called `__fastcall` but
    whose instructions show a plain this-call (ECX only) become `__thiscall`.
    Returns {convention: functions changed}."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    out: dict[str, int] = {}
    if int(program.getDefaultPointerSize()) != 4 or str(program.getLanguage().getProcessor()) != "x86":
        return out
    listing, fm = program.getListing(), program.getFunctionManager()
    known = {str(c.getName()) for c in program.getCompilerSpec().getCallingConventions()}
    for f in fm.getFunctions(True):
        if monitor is not None and monitor.isCancelled():
            break
        if f.isExternal() or f.isThunk() or _is_stub(f):
            continue
        current = str(f.getCallingConventionName() or "")
        relabel = relabel_fastcall and current == FASTCALL
        if current not in UNSET_CONVENTIONS and not relabel:
            continue
        if f.getSignatureSource() == SourceType.USER_DEFINED:
            continue
        entry = f.getEntryPoint()
        conv = classify_convention(_entry_path(listing, fm, entry),
                                   _ret_sizes(listing, f.getBody()),
                                   _call_sites(program, listing, fm, entry))
        if conv is None or conv not in known or (relabel and conv != THISCALL):
            continue
        try:
            if relabel:
                _relabel_thiscall(program, f)
            else:
                f.setCallingConvention(conv)
        except Exception:  # one odd function must not stop the pass
            continue
        out[conv] = out.get(conv, 0) + 1
    return out


# -- Decompiler Parameter ID, run once over the whole program ---------------------------

PARAM_ID_NAME = "Decompiler Parameter ID"
PARAM_ID_MIN_UNKNOWN = 0.05   # run it when more than this share of functions has no convention


def unknown_share(program: Any) -> float:
    """Share of the non-thunk, non-external functions whose calling convention is unset."""
    total = unset = 0
    for f in program.getFunctionManager().getFunctions(True):
        if f.isExternal() or f.isThunk() or _is_stub(f):
            continue
        total += 1
        if str(f.getCallingConventionName() or "") in UNSET_CONVENTIONS:
            unset += 1
    return unset / total if total else 0.0


def run_parameter_id(program: Any, monitor: Any) -> bool:
    """Run the Decompiler Parameter ID analyzer once over all code. It decompiles every
    function (about 6 ms each on x86) and sets convention, parameters and types. Ghidra's
    auto-analysis leaves large static-CRT binaries mostly without a convention. Must run
    inside a transaction, with the script bundle host referenced. False when the analyzer
    does not exist."""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore
    from ghidra.app.services import Analyzer  # type: ignore
    from ghidra.util.classfinder import ClassSearcher  # type: ignore

    analyzer = next((a for a in ClassSearcher.getInstances(Analyzer)
                     if str(a.getName()) == PARAM_ID_NAME), None)
    if analyzer is None:
        return False
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.initializeOptions()
    mgr.scheduleOneTimeAnalysis(analyzer, program.getMemory().getLoadedAndInitializedAddressSet())
    mgr.startAnalysis(monitor, True)
    return True


def apply_all(program: Any, monitor: Any = None, parameter_id: bool = True) -> dict[str, Any]:
    """All post-analysis fixups, idempotent. Must run inside a transaction.

    1. prolog helpers named and given their call fixup;
    2. Decompiler Parameter ID over the whole program when `parameter_id` and more than
       PARAM_ID_MIN_UNKNOWN of the functions have no convention;
    3. functions it called `__fastcall` that only take ECX become `__thiscall` (it tries
       fastcall first, which is wrong for plain this-calls);
    4. functions still without a convention are classified from their instructions;
    5. Delphi string literals typed as strings and the integer parameters that receive them retyped as
       string pointers, so the decompiler prints ``L"text"``; concatenation calls get a variadic signature
       (x64) or a comment with the pieces (x86) (``delphistr``; nothing on other programs)."""
    from . import delphistr
    out: dict[str, Any] = {"call_fixups": apply_call_fixups(program)}
    out["unknown_before"] = round(unknown_share(program), 3)
    if parameter_id and out["unknown_before"] > PARAM_ID_MIN_UNKNOWN \
            and not (monitor is not None and monitor.isCancelled()):
        out["parameter_id"] = run_parameter_id(program, monitor)
    if not (monitor is not None and monitor.isCancelled()):
        out["conventions"] = apply_conventions(program, monitor, relabel_fastcall=True)
    out["unknown_after"] = round(unknown_share(program), 3)
    if not (monitor is not None and monitor.isCancelled()):
        out["delphi_strings"] = delphistr.apply_delphi_strings(program, monitor)
    return out
