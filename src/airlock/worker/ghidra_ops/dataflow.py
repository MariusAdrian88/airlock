"""dataflow ops: switch_tables, trace_values, constants (DESIGN 6 "dataflow").

* ``switch_tables(program, entry)``: the jump tables the decompiler recovered for one function. Rows
  ``[switch_addr, [[label, target], ...], default_target | null, n_cases]`` (labels grouped per target by the server).
* ``trace_values(program, entry, variable | param, depth)``: def-use chain of one decompiler variable
  (high p-code). Rows ``[depth, kind, addr, text]`` with kinds ``def``, ``use``, ``alias``, ``call``, ``store``,
  ``cmp``, ``return``, ``into`` (the value enters a callee parameter, depth > 0) and ``note``.
* ``constants(program, value, limit)``: functions with an instruction that has the scalar ``value``. The search
  is a byte search for the immediate encodings (32-bit, 16-bit, 64-bit) in executable blocks, then a check of the
  instruction operands, so the cost is far below a walk over all instructions.
"""

from __future__ import annotations

import re
import time
from typing import Any

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from . import stubs
from .decompile import _decomp, _resolve_function, check_open
from .session import guarded

DECOMPILE_TIMEOUT_S = 60
MAX_LINES = 120
MAX_HITS = 400000
DEFAULT_LABEL = 0xBAD1ABE1          # the decompiler's label value for the default branch of a jump table

_PASS_THROUGH = {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "MULTIEQUAL", "INDIRECT", "SUBPIECE", "PIECE", "PTRSUB",
                 "PTRADD", "INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT",
                 "INT_SRIGHT", "INT_MULT", "FLOAT2FLOAT", "INT2FLOAT", "TRUNC", "INT_NEGATE", "INT_2COMP"}
_COMPARE = {"INT_EQUAL": "==", "INT_NOTEQUAL": "!=", "INT_LESS": "<u", "INT_SLESS": "<", "INT_LESSEQUAL": "<=u",
            "INT_SLESSEQUAL": "<="}


def _addr(a: Any) -> int | None:
    try:
        return S.addr_int(a) if a is not None else None
    except Exception:  # noqa: BLE001
        return None


def _decompile(e: Any, di: Any, func: Any, timeout: int) -> Any:
    from ghidra.util.task import TaskMonitor  # type: ignore
    res = di.decompileFunction(func, timeout, TaskMonitor.DUMMY)
    if res.isTimedOut() or not res.decompileCompleted() or res.getHighFunction() is None:
        raise WorkerError("decompile_failed", f"cannot decompile {func.getName()}: "
                          f"{str(res.getErrorMessage() or 'timeout').strip()}")
    return res


# ── switch_tables ──────────────────────────────────────────────────────────

@op("switch_tables")
@guarded
def switch_tables(args: dict[str, Any]) -> dict[str, Any]:
    """switch_tables(program, entry, timeout=60): recovered jump tables of the function."""
    e = S.ready_entry(args.get("program"))
    timeout = int(args.get("timeout") or DECOMPILE_TIMEOUT_S)
    with S.POOL.foreground(), e.fg, e.lock.read():
        check_open(e)
        func = _resolve_function(e.program, args.get("entry"))
        if func.isExternal():
            raise WorkerError("no_function", f"'{func.getName()}' is an external function")
        res = _decompile(e, _decomp(e), func, timeout)
        hf = res.getHighFunction()
        rows: list[list[Any]] = []
        for jt in hf.getJumpTables() or []:
            cases = [_addr(a) for a in jt.getCases()]
            labels = [int(v) & 0xFFFFFFFF if v is not None else None for v in jt.getLabelValues()]
            pairs = [[lb, t] for lb, t in zip(labels, cases)]
            default = next((t for lb, t in pairs if lb == DEFAULT_LABEL), None)
            pairs = [p for p in pairs if p[0] != DEFAULT_LABEL]
            rows.append([_addr(jt.getSwitchAddress()), pairs, default, len(cases)])
        return {"entry": _addr(func.getEntryPoint()), "name": str(func.getName()), "switches": rows}


# ── trace_values ───────────────────────────────────────────────────────────

class _Tracer:
    def __init__(self, e: Any, di: Any, timeout: int) -> None:
        self.e, self.di, self.timeout = e, di, timeout
        self.rows: list[list[Any]] = []
        self.seen: set[Any] = set()
        self.program = e.program
        self.fm = e.program.getFunctionManager()

    def full(self) -> bool:
        return len(self.rows) >= MAX_LINES

    def name(self, vn: Any) -> str:
        if vn is None:
            return "?"
        if vn.isConstant():
            return hex(int(vn.getOffset()) & 0xFFFFFFFFFFFFFFFF)
        hv = vn.getHigh()
        if hv is not None:
            nm = hv.getName()
            if nm and str(nm) != "UNNAMED":
                return str(nm)
        if vn.isUnique():
            return f"t{int(vn.getOffset()) & 0xFFFFFF:x}"
        if vn.isAddress():
            return f"mem_{int(vn.getOffset()):x}"
        return str(vn.getAddress())

    def callee(self, opx: Any) -> tuple[str, Any]:
        tgt = opx.getInput(0)
        if tgt is not None and tgt.isAddress():
            f = self.fm.getFunctionAt(tgt.getAddress())
            if f is not None:
                return str(f.getName(True)), f
            return f"0x{int(tgt.getOffset()):x}", None
        return "indirect", None

    def add(self, depth: int, kind: str, opx: Any, text: str) -> None:
        if not self.full():
            self.rows.append([depth, kind, _addr(opx.getSeqnum().getTarget()) if opx is not None else None, text])

    def opname(self, opx: Any) -> str:
        return str(opx.getMnemonic())

    def trace_vn(self, vn: Any, depth: int, level: int, fn_label: str) -> None:
        """Follow ``vn`` forward through its descendants."""
        key = (fn_label, int(vn.getOffset()), str(vn.getAddress().getAddressSpace().getName()),
               vn.getPCAddress().getOffset() if vn.getPCAddress() is not None else 0, int(vn.getSize()))
        if key in self.seen or self.full():
            return
        self.seen.add(key)
        for opx in list(vn.getDescendants() or []):
            if self.full():
                return
            m = self.opname(opx)
            if m in ("CALL", "CALLIND", "CALLOTHER"):
                idx = next((i for i in range(1, opx.getNumInputs()) if opx.getInput(i) is not None
                            and opx.getInput(i).equals(vn)), None) if m != "CALLOTHER" else None
                nm, f = self.callee(opx) if m == "CALL" else ("indirect" if m == "CALLIND" else "intrinsic", None)
                if idx is None:
                    self.add(level, "call", opx, f"{nm}(... {self.name(vn)} ...)")
                    continue
                args_ = ", ".join(self.name(opx.getInput(i)) for i in range(1, min(opx.getNumInputs(), 7)))
                self.add(level, "call", opx, f"{nm}({args_}) arg {idx}")
                if f is not None and depth > 0 and not f.isExternal() and not f.isThunk():
                    self.into(f, idx - 1, depth - 1, level + 1)
                out = opx.getOutput()
                if out is not None and m == "CALL" and False:
                    self.trace_vn(out, depth, level, fn_label)
            elif m == "STORE":
                self.add(level, "store", opx, f"*({self.name(opx.getInput(1))}) = {self.name(opx.getInput(2))}")
            elif m == "LOAD":
                self.add(level, "use", opx, f"{self.name(opx.getOutput())} = *({self.name(opx.getInput(1))})")
            elif m in _COMPARE:
                a, b = opx.getInput(0), opx.getInput(1)
                self.add(level, "cmp", opx, f"{self.name(a)} {_COMPARE[m]} {self.name(b)}")
            elif m == "RETURN":
                self.add(level, "return", opx, f"return {self.name(vn)}")
            elif m == "CBRANCH":
                continue
            elif m in _PASS_THROUGH:
                out = opx.getOutput()
                if out is None:
                    continue
                if out.getHigh() is not None and vn.getHigh() is not None and out.getHigh() == vn.getHigh():
                    self.trace_vn(out, depth, level, fn_label)
                    continue
                if m in ("CAST", "COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "MULTIEQUAL", "INDIRECT"):
                    self.trace_vn(out, depth, level, fn_label)       # same value, new name: no line
                    continue
                sym = {"INT_ADD": "+", "PTRSUB": "+", "PTRADD": "+", "INT_SUB": "-", "INT_AND": "&", "INT_OR": "|",
                       "INT_XOR": "^", "INT_LEFT": "<<", "INT_RIGHT": ">>u", "INT_SRIGHT": ">>", "INT_MULT": "*"}.get(m)
                ins_ = [self.name(opx.getInput(i)) for i in range(opx.getNumInputs())]
                text = f"{self.name(out)} = {(' ' + sym + ' ').join(ins_)}" if sym and len(ins_) == 2                     else f"{self.name(out)} = {m}({', '.join(ins_)})"
                self.add(level, "alias", opx, text)
                self.trace_vn(out, depth, level, fn_label)
            else:
                self.add(level, "use", opx, f"{m} {', '.join(self.name(opx.getInput(i)) for i in range(opx.getNumInputs()))}")

    def into(self, f: Any, param_idx: int, depth: int, level: int) -> None:
        try:
            res = _decompile(self.e, self.di, f, self.timeout)
        except WorkerError:
            return
        hf = res.getHighFunction()
        sym = hf.getLocalSymbolMap().getParamSymbol(param_idx)
        if sym is None:
            return
        hv = sym.getHighVariable()
        if hv is None:
            return
        self.add(level, "into", None, f"{f.getName(True)} param_{param_idx + 1}")
        for inst in hv.getInstances():
            self.trace_vn(inst, depth, level, str(f.getEntryPoint()))


def _find_roots(hf: Any, variable: str | None, param: int | None) -> list[Any]:
    lsm = hf.getLocalSymbolMap()
    if param is not None:
        sym = lsm.getParamSymbol(param - 1)
        if sym is None:
            raise WorkerError("no_variable", f"the function has no parameter {param}")
        hv = sym.getHighVariable()
        return list(hv.getInstances()) if hv is not None else []
    want = (variable or "").strip()
    for sym in lsm.getSymbols():
        if str(sym.getName()) == want and sym.getHighVariable() is not None:
            return list(sym.getHighVariable().getInstances())
    # a name the decompiler shows only in the C text (iVar3): look at all high variables
    it = hf.getLocalSymbolMap().getSymbols()
    names = sorted({str(s.getName()) for s in it})
    raise WorkerError("no_variable", f"no variable '{want}' in the decompiled function. Variables: "
                      + ", ".join(names[:30]))


@op("trace_values")
@guarded
def trace_values(args: dict[str, Any]) -> dict[str, Any]:
    """trace_values(program, entry, variable=None, param=None, depth=2, timeout=60)."""
    e = S.ready_entry(args.get("program"))
    timeout = int(args.get("timeout") or DECOMPILE_TIMEOUT_S)
    depth = max(0, min(int(args.get("depth") if args.get("depth") is not None else 2), 5))
    variable = args.get("variable")
    param = int(args["param"]) if args.get("param") else None
    if not variable and not param:
        raise WorkerError("bad_args", "pass variable= or param=")
    with S.POOL.foreground(), e.fg, e.lock.read():
        check_open(e)
        func = _resolve_function(e.program, args.get("entry"))
        if func.isExternal():
            raise WorkerError("no_function", f"'{func.getName()}' is an external function")
        di = _decomp(e)
        res = _decompile(e, di, func, timeout)
        hf = res.getHighFunction()
        roots = _find_roots(hf, variable, param)
        tr = _Tracer(e, di, timeout)
        label = str(func.getEntryPoint())
        for vn in roots:
            d = vn.getDef()
            if d is not None and not tr.full():
                m = tr.opname(d)
                if m == "CALL":
                    nm, _f = tr.callee(d)
                    tr.add(0, "def", d, f"= {nm}(" + ", ".join(tr.name(d.getInput(i))
                           for i in range(1, min(d.getNumInputs(), 7))) + ")")
                elif m == "LOAD":
                    tr.add(0, "def", d, f"= *({tr.name(d.getInput(1))})")
                elif m == "COPY" and d.getInput(0).isConstant():
                    tr.add(0, "def", d, f"= {tr.name(d.getInput(0))}")
                elif m == "MULTIEQUAL":
                    pass
                else:
                    tr.add(0, "def", d, f"= {m}(" + ", ".join(tr.name(d.getInput(i))
                           for i in range(d.getNumInputs())) + ")")
            elif d is None and vn.isInput():
                tr.rows.append([0, "note", None, f"{tr.name(vn)} is a parameter or an input of the function"]) \
                    if not any(r[1] == "note" for r in tr.rows) else None
        for vn in roots:
            tr.trace_vn(vn, depth, 0, label)
        return {"entry": _addr(func.getEntryPoint()), "name": str(func.getName()), "rows": tr.rows,
                "truncated": tr.full()}


# ── constants ──────────────────────────────────────────────────────────────

def _patterns(value: int) -> list[bytes]:
    out: list[bytes] = []
    v64 = value & 0xFFFFFFFFFFFFFFFF
    if v64 <= 0xFFFFFFFF or value < 0 and value >= -0x80000000:
        out.append((value & 0xFFFFFFFF).to_bytes(4, "little"))
        if 0 <= value <= 0xFFFF:
            out.append(value.to_bytes(2, "little"))
    else:
        out.append(v64.to_bytes(8, "little"))
    return out


@op("constants")
@guarded
def constants(args: dict[str, Any]) -> dict[str, Any]:
    """constants(program, value, limit=30): functions that hold the immediate ``value``."""
    import jpype
    from ghidra.util.task import TaskMonitor  # type: ignore

    e = S.ready_entry(args.get("program"))
    value = int(args["value"])
    limit = max(1, int(args.get("limit") or 30))
    t0 = time.monotonic()
    pats = _patterns(value)
    uvals = {value & 0xFFFFFFFFFFFFFFFF, value & 0xFFFFFFFF}
    with e.lock.read():
        check_open(e)
        prog = e.program
        mem, listing, fm = prog.getMemory(), prog.getListing(), prog.getFunctionManager()
        found: dict[int, list[int]] = {}
        hits = 0
        seen_ins: set[int] = set()
        for block in mem.getBlocks():
            if not block.isExecute() or not block.isInitialized() or str(block.getName()) == stubs.STUB_BLOCK:
                continue
            end = block.getEnd()
            for pat in pats:
                jb = jpype.JArray(jpype.JByte)([b - 256 if b > 127 else b for b in pat])
                mask = jpype.JArray(jpype.JByte)([-1] * len(pat))
                start = block.getStart()
                while start is not None and hits < MAX_HITS:
                    hit = mem.findBytes(start, end, jb, mask, True, TaskMonitor.DUMMY)
                    if hit is None:
                        break
                    hits += 1
                    nxt = hit.add(1) if hit.compareTo(end) < 0 else None
                    start = nxt
                    ins = listing.getInstructionContaining(hit)
                    if ins is None:
                        continue
                    ia = _addr(ins.getAddress())
                    if ia in seen_ins:
                        continue
                    if not _ins_has(ins, uvals, value):
                        continue
                    seen_ins.add(ia)
                    f = fm.getFunctionContaining(ins.getAddress())
                    key = _addr(f.getEntryPoint()) if f is not None else -1
                    found.setdefault(key, []).append(ia)
        rows = sorted(([k, len(v), min(v)] for k, v in found.items()), key=lambda r: (-r[1], r[0]))
        return {"rows": rows[:limit * 4], "total": len(rows), "secs": round(time.monotonic() - t0, 1)}


def _ins_has(ins: Any, uvals: set[int], value: int) -> bool:
    for i in range(ins.getNumOperands()):
        for o in ins.getOpObjects(i):
            if hasattr(o, "getUnsignedValue") and hasattr(o, "getSignedValue"):
                try:
                    u = int(o.getUnsignedValue())
                    s = int(o.getSignedValue())
                except Exception:  # noqa: BLE001
                    continue
                if u in uvals or s == value or (u & 0xFFFFFFFF) in uvals:
                    return True
    return False


_ = re
