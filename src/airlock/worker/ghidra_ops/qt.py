"""qt_dispatch op: what needs code for the Qt metaobjects the server parsed from the PE bytes.

Per class (``meta`` = address of staticMetaObject, ``metacall`` = ``d.static_metacall``):

* ``cases``: moc writes ``qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)`` with a
  ``switch (_id)`` whose case N calls the function behind method N. The decompiler output of the dispatcher
  is walked token by token: every ``switch`` is scanned, the one whose case labels fit the method count best
  (the first on a tie) is the InvokeMetaMethod switch, and the first call to a function of the program inside
  each case is the method. A case without such a call (the body was inlined) maps nothing.
* ``parent``: for a class whose ``d.superdata`` is 0 in the file (the superclass is imported, the compiler
  fills the field at start-up) the writes to that field are looked up; the instructions just before the store
  read the import ``staticMetaObject`` of the parent, whose mangled name gives the class name.

Result: {"classes": [{"meta", "cases": {idx: entry}, "parent", "status"}], "secs"}.
"""

from __future__ import annotations

import re
import time
from typing import Any

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from .decompile import _decomp, _resolve_function, check_open
from .project import dispose_decomp
from .session import guarded

MAX_CLASSES = 5000
DECOMPILE_TIMEOUT_S = 30
BACK_INSNS = 8

_MSVC = re.compile(r"\?staticMetaObject@((?:[A-Za-z_]\w*@)+)@")
_DEMANGLED = re.compile(r"([A-Za-z_][\w:]*)::staticMetaObject\b")
_NUM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+)[uUlL]*$")


def parent_from_symbol(name: str) -> str:
    """Class name out of the import name of ``staticMetaObject`` (MSVC, Itanium or demangled form)."""
    m = _MSVC.search(name)
    if m:
        return "::".join(reversed([p for p in m.group(1).split("@") if p]))
    m = _DEMANGLED.search(name)
    if m:
        return m.group(1)
    i = name.find("_ZN")
    if i >= 0 and "16staticMetaObjectE" in name:
        rest, parts = name[i + 3:], []
        while True:
            n = re.match(r"(\d+)", rest)
            if not n:
                break
            k = int(n.group(1))
            word = rest[len(n.group(1)):len(n.group(1)) + k]
            rest = rest[len(n.group(1)) + k:]
            if word == "staticMetaObject":
                break
            parts.append(word)
        if parts:
            return "::".join(parts)
    return ""


def _num(text: str) -> int | None:
    t = text.strip()
    if not _NUM.match(t):
        return None
    try:
        return int(t.rstrip("uUlL"), 0)
    except ValueError:
        return None


def _internal_call(tok: Any, fm: Any) -> int | None:
    """Entry of the program function a ClangFuncNameToken calls, None for other tokens, external callees,
    thunks to imports and indirect calls."""
    from ghidra.program.model.pcode import PcodeOp  # type: ignore
    op_ = tok.getPcodeOp()
    if op_ is None or int(op_.getOpcode()) != PcodeOp.CALL:
        return None
    tgt = op_.getInput(0)
    if tgt is None:
        return None
    f = fm.getFunctionAt(tgt.getAddress())
    if f is None or f.isExternal():
        return None
    if f.isThunk():
        t = f.getThunkedFunction(True)
        if t is not None and t.isExternal():
            return None
    return S.addr_int(tgt.getAddress())


def _function_named(program: Any, text: str) -> int | None:
    """Entry of the function a decompiler token names (``FUN_00401990`` or a symbol name)."""
    fm = program.getFunctionManager()
    m = re.match(r"^FUN_([0-9a-fA-F]+)$", text)
    if m:
        a = program.getAddressFactory().getDefaultAddressSpace().getAddress(int(m.group(1), 16))
        f = fm.getFunctionAt(a)
        return S.addr_int(f.getEntryPoint()) if f is not None else None
    for sym in program.getSymbolTable().getGlobalSymbols(text):
        f = fm.getFunctionAt(sym.getAddress())
        if f is not None:
            return S.addr_int(f.getEntryPoint())
    return None


def scan_dispatcher(markup: Any, program: Any, idvar: str) -> dict[str, Any]:
    """Walk the decompiled dispatcher token by token.

    Returns {"switches": [{case: entry|None}], "ifs": {case: entry|None}, "signals": {index: entry}}:
    ``switches`` one dict per ``switch`` statement (token order); ``ifs`` the blocks ``if (idvar == K) {...}`` of
    classes small enough for the compiler to skip the switch; ``signals`` the pointer comparisons of the
    IndexOfMethod branch (``== signalFunction`` then ``*result = index``)."""
    from ghidra.app.decompiler import ClangFuncNameToken  # type: ignore

    fm = program.getFunctionManager()
    toks = []
    it = markup.tokenIterator(True)
    while it.hasNext():
        tok = it.next()
        text = str(tok.getText()).strip()
        if text:
            toks.append((text, tok))
    switches: list[dict[int, int | None]] = []
    ifs: dict[int, int | None] = {}
    signals: dict[int, int] = {}
    stack: list[dict[str, Any]] = []   # {"cases": {}, "depth": int, "open": [labels], "kind": "switch"|"if"}
    depth = 0
    pending: dict[str, Any] | None = None
    first_call: int | None = None
    last_ref: tuple[int, int] | None = None     # (token index, entry) of the last "== function" reference
    n = len(toks)
    i = 0
    while i < n:
        text, tok = toks[i]
        nxt = toks[i + 1][0] if i + 1 < n else ""
        if i > 0 and toks[i - 1][0] == "==" and _num(text) is None and text != "(":
            ref = _function_named(program, text)
            if ref is not None:
                last_ref = (i, ref)
        if text == "switch":
            pending = {"cases": {}, "kind": "switch", "open": []}
        elif idvar and text == idvar and nxt == "==" and i + 3 < n and _num(toks[i + 2][0]) is not None \
                and toks[i + 3][0] == ")":
            pending = {"cases": ifs, "kind": "if", "open": [_num(toks[i + 2][0])]}
            ifs.setdefault(pending["open"][0], None)
        elif text == "{":
            depth += 1
            if pending is not None:
                pending["depth"] = depth
                stack.append(pending)
                pending = None
        elif text == "}":
            if stack and stack[-1]["depth"] == depth:
                top = stack.pop()
                if top["kind"] == "switch":
                    switches.append(top["cases"])
            depth -= 1
        elif text == "case" and stack and stack[-1]["kind"] == "switch":
            v = _num(toks[i + 1][0]) if i + 1 < n else None
            if v is not None:
                sw = stack[-1]
                sw["cases"].setdefault(v, None)
                sw["open"].append(v)
                i += 1
        elif text in ("default", "break", "return") and stack:
            if stack[-1]["kind"] == "switch":
                stack[-1]["open"] = []
        elif isinstance(tok, ClangFuncNameToken):
            entry = _internal_call(tok, fm)
            if entry is not None:
                if first_call is None:
                    first_call = entry
                if stack and stack[-1]["open"]:
                    for v in stack[-1]["open"]:
                        if stack[-1]["cases"].get(v) is None:
                            stack[-1]["cases"][v] = entry
                    if stack[-1]["kind"] == "switch":
                        stack[-1]["open"] = []
                    else:
                        stack[-1]["open"] = []
        elif text == "=" and last_ref is not None and i - last_ref[0] <= 40 and i + 2 < n \
                and toks[i + 2][0] == ";" and _num(toks[i + 1][0]) is not None:
            signals.setdefault(_num(toks[i + 1][0]), last_ref[1])
            last_ref = None
        i += 1
    return {"switches": switches, "ifs": ifs, "signals": signals, "first_call": first_call}


def pick_switch(switches: list[dict[int, int | None]], nmethods: int) -> dict[int, int | None]:
    """The InvokeMetaMethod switch: case labels inside ``0..nmethods-1`` covering most indices, earliest first."""
    best: dict[int, int | None] = {}
    best_score = -1
    for sw in switches:
        labels = [k for k in sw if 0 <= k < nmethods]
        if not labels or len(labels) < len(sw) * 0.9:
            continue
        score = len(labels)
        if score > best_score:
            best, best_score = sw, score
    return best


def _names_near(program: Any, ins: Any) -> list[str]:
    """Symbol / import names the instruction refers to (directly or through an import slot)."""
    out: list[str] = []
    symtab = program.getSymbolTable()
    listing = program.getListing()
    for ref in ins.getReferencesFrom():
        if ref.isExternalReference():
            loc = ref.getExternalLocation()
            if loc is not None:
                out += [str(loc.getLabel()), str(loc.getOriginalImportedName() or "")]
            continue
        to = ref.getToAddress()
        if to is None or not to.isMemoryAddress():
            continue
        for sym in symtab.getSymbols(to):
            out.append(str(sym.getName()))
        d = listing.getDataAt(to)
        if d is not None:
            for r2 in d.getReferencesFrom():
                if r2.isExternalReference():
                    loc = r2.getExternalLocation()
                    if loc is not None:
                        out += [str(loc.getLabel()), str(loc.getOriginalImportedName() or "")]
    return [n for n in out if n]


def _source_register(ins: Any) -> Any:
    """The register a store ``MOV [meta], reg`` writes, None when the source is not a register."""
    try:
        if ins.getNumOperands() < 2:
            return None
        for o in ins.getOpObjects(1):
            if hasattr(o, "getName") and o.getClass().getSimpleName() == "Register":
                return o
    except Exception:  # noqa: BLE001
        return None
    return None


def _writes_register(ins: Any, reg: Any) -> bool:
    try:
        return any(hasattr(o, "getName") and o.getClass().getSimpleName() == "Register"
                   and str(o.getBaseRegister()) == str(reg.getBaseRegister()) for o in ins.getOpObjects(0))
    except Exception:  # noqa: BLE001
        return False


def find_parent(program: Any, meta: int) -> str:
    """Parent class of a metaobject whose superdata the program writes at start-up: the store
    ``MOV [staticMetaObject], reg`` is traced back to the load of the import ``Parent::staticMetaObject``."""
    space = program.getAddressFactory().getDefaultAddressSpace()
    addr = space.getAddress(meta)
    listing = program.getListing()
    for ref in program.getReferenceManager().getReferencesTo(addr):
        if not ref.getReferenceType().isWrite():
            continue
        store = listing.getInstructionAt(ref.getFromAddress())
        if store is None:
            continue
        reg = _source_register(store)
        ins, n = store.getPrevious(), 0
        while ins is not None and n < BACK_INSNS * 6:
            if reg is None or _writes_register(ins, reg):
                for name in _names_near(program, ins):
                    if "staticMetaObject" in name:
                        cls = parent_from_symbol(name)
                        if cls:
                            return cls
                if reg is not None:
                    break
            ins = ins.getPrevious()
            n += 1
    return ""


@op("qt_dispatch")
@guarded
def qt_dispatch(args: dict[str, Any]) -> dict[str, Any]:
    """qt_dispatch(program, classes=[{meta, metacall, nmethods, need_parent}], timeout=30): see the module doc."""
    e = S.ready_entry(args.get("program"))
    from ghidra.util.task import TaskMonitor  # type: ignore

    classes = args.get("classes")
    if not isinstance(classes, list) or len(classes) > MAX_CLASSES:
        raise WorkerError("bad_args", f"classes must be a list of at most {MAX_CLASSES} entries")
    timeout = int(args.get("timeout") or DECOMPILE_TIMEOUT_S)
    t0 = time.monotonic()
    out: list[dict[str, Any]] = []
    with S.POOL.foreground(), e.fg, e.lock.read():
        check_open(e)
        di = _decomp(e)
        for c in classes:
            res: dict[str, Any] = {"meta": int(c["meta"]), "cases": {}, "parent": "", "status": "ok"}
            try:
                if c.get("need_parent"):
                    res["parent"] = find_parent(e.program, int(c["meta"]))
                mc = c.get("metacall")
                if mc:
                    try:
                        func = _resolve_function(e.program, int(mc))
                    except WorkerError:
                        res["status"] = "no_function"
                    else:
                        dres = di.decompileFunction(func, timeout, TaskMonitor.DUMMY)
                        if dres.isTimedOut() or not dres.decompileCompleted():
                            res["status"] = "timeout" if dres.isTimedOut() else "decompile_error"
                        else:
                            hf = dres.getHighFunction()
                            idvar = ""
                            try:
                                psym = hf.getLocalSymbolMap().getParamSymbol(2)
                                idvar = str(psym.getName()) if psym is not None else ""
                            except Exception:  # noqa: BLE001  fewer than three parameters
                                idvar = ""
                            sc = scan_dispatcher(dres.getCCodeMarkup(), e.program, idvar)
                            nm = int(c.get("nmethods") or 0)
                            pick = pick_switch(sc["switches"], nm)
                            if not pick:
                                pick = {k: v for k, v in sc["ifs"].items() if 0 <= k < max(nm, 1)}
                            cases = {k: v for k, v in pick.items() if v is not None}
                            if nm == 1 and not cases and sc["first_call"] is not None:
                                cases = {0: sc["first_call"]}     # one method: moc emits no switch on the id
                            for k, v in sc["signals"].items():
                                cases.setdefault(k, v)
                            res["cases"] = cases
                            res["labels"] = len(pick)
                            if not pick and not cases:
                                res["status"] = "no_switch"
            except Exception as ex:  # noqa: BLE001  one class must not stop the others
                res["status"] = f"error:{type(ex).__name__}"
            out.append(res)
    return {"classes": out, "secs": round(time.monotonic() - t0, 1)}


# ── pointer-to-member connects ─────────────────────────────────────────────
#
# ``QObject::connect(sender, &S::sig, receiver, &R::slot)`` compiles to a call of the imported
# ``QObject::connectImpl(sender, void **signal, receiver, void **slot, QSlotObjectBase *obj, ...)``. The compiler
# keeps the template instantiation as a small function of its own (the decompiler even shows the stack
# arguments of the import shifted by one), so the call site holds only parameters: the pointer to the signal
# member pointer, and a slot object ``new``-ed with ``impl`` at +8 and the slot (a member pointer or a lambda) at
# +0x10. The member pointers are constants in the callers. ``_Flow`` gives the value of a varnode in terms of
# constants, parameters and stack slots; ``qt_connects`` chases the signal and the slot up the callers until the
# signal is a constant. The connection is filed at the call that has the constants (the user's ``connect``).

MAX_SITES = 20000
MAX_DEPTH = 4
MAX_CALLERS = 12
MAX_FLOWS = 6000
VTABLE_MAX = 0x4000        # an odd member pointer below this is an Itanium virtual one (vtable offset + 1)
_PASS = frozenset({"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "INDIRECT"})


def _signed(v: int, size: int = 8) -> int:
    """``v`` as a signed number of ``size`` bytes (constants of a 32-bit program are 4 bytes wide)."""
    bits = max(1, size) * 8
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >= 1 << (bits - 1) else v


class _Flow:
    """Symbolic values of one decompiled function: ``("const", a)``, ``("param", i, d)`` (parameter ``i`` read
    through ``d`` pointers), ``("stack", off)`` (address of a stack slot) or ``("new", id, off)`` (a call result
    plus an offset)."""

    def __init__(self, hf: Any) -> None:
        self.hf = hf
        self._imm: dict[int, list[tuple[Any, int]]] | None = None
        self.psize = int(hf.getFunction().getProgram().getDefaultPointerSize())
        self.ops = list(hf.getPcodeOps())
        self._stack: dict[int, list[Any]] = {}      # stack offset -> ops that store there (value = input 0 / 2)
        self._late: list[Any] = []
        for p in self.ops:
            out = p.getOutput()
            if out is not None and out.getAddress().isStackAddress()                     and p.getMnemonic() in ("COPY", "INDIRECT", "MULTIEQUAL", "PTRSUB", "CAST"):
                self._stack.setdefault(_signed(int(out.getAddress().getOffset())), []).append(p)
            elif p.getMnemonic() == "STORE":
                self._late.append(p)
        for p in self._late:            # STORE through the address of a stack slot
            ptr = self.value(p.getInput(1))
            if ptr is not None and ptr[0] == "stack":
                self._stack.setdefault(ptr[1], []).append(p)

    def calls(self) -> list[Any]:
        return [p for p in self.ops if p.getMnemonic() in ("CALL", "CALLIND")]

    def call_at(self, addr: Any) -> Any:
        it = self.hf.getPcodeOps(addr)
        while it.hasNext():
            p = it.next()
            if p.getMnemonic() in ("CALL", "CALLIND"):
                return p
        return None

    def param_index(self, vn: Any) -> int | None:
        try:
            hv = vn.getHigh()
            sym = hv.getSymbol() if hv is not None else None
            if sym is not None and sym.isParameter():
                return int(sym.getCategoryIndex())
        except Exception:  # noqa: BLE001
            return None
        return None

    def value(self, vn: Any, depth: int = 0) -> tuple | None:
        if vn is None or depth > 14:
            return None
        if vn.isConstant():
            return ("const", int(vn.getOffset()))
        if vn.getAddress().isMemoryAddress():
            return ("mem", int(vn.getAddress().getOffset()))          # a value read from a global (an import slot)
        d = vn.getDef()
        if d is None:
            i = self.param_index(vn)
            return ("param", i, 0) if i is not None else None
        name = d.getMnemonic()
        if name in _PASS:
            return self.value(d.getInput(0), depth + 1)
        if name == "MULTIEQUAL":
            vals = {self.value(d.getInput(k), depth + 1) for k in range(d.getNumInputs())} - {("const", 0)}
            return vals.pop() if len(vals) == 1 and None not in vals else None
        if name in ("PTRSUB", "INT_ADD", "PTRADD"):
            a, b = d.getInput(0), d.getInput(1)
            if name == "PTRSUB" and a.isRegister() and b.isConstant():
                return ("stack", _signed(int(b.getOffset()), b.getSize()))
            if name == "PTRSUB" and a.isConstant() and b.isConstant():
                return ("const", int(b.getOffset()))          # address of a global
            base = self.value(a, depth + 1)
            if base is not None and b.isConstant():
                off = _signed(int(b.getOffset()), b.getSize()) * (int(d.getInput(2).getOffset()) if name == "PTRADD" else 1)
                if base[0] == "stack":
                    return ("stack", base[1] + off)
                if base[0] == "new":
                    return ("new", base[1], base[2] + off)
            return None
        if name == "LOAD":
            p = self.value(d.getInput(1), depth + 1)
            if p is not None and p[0] == "const":
                return ("mem", p[1])            # the content of a global (an import slot)
            return self.deref(p, depth + 1)
        if name in ("CALL", "CALLIND"):
            return ("new", (int(d.getSeqnum().getTarget().getOffset()), int(d.getSeqnum().getTime())), 0)
        return None

    def deref(self, p: tuple | None, depth: int = 0, before: Any = None) -> tuple | None:
        """The value stored where pointer ``p`` points; for a stack slot the last store before ``before``
        (an address) in address order, the only store without ``before``."""
        if p is None:
            return None
        if p[0] == "stack":
            ops = self._stack.get(p[1], [])
            got = None
            if before is not None:
                ops = [o for o in ops if o.getSeqnum().getTarget().compareTo(before) < 0]
                if ops:
                    last = max(ops, key=lambda o: (o.getSeqnum().getTarget().getOffset(), o.getSeqnum().getTime()))
                    got = self.slot_value(last, depth + 1)
            else:
                vals = {self.slot_value(op, depth + 1) for op in ops if op.getMnemonic() != "INDIRECT"}
                got = vals.pop() if len(vals) == 1 and None not in vals else None
            return got if got is not None else self.imm_store(p[1], before)
        if p[0] == "param":
            return ("param", p[1], p[2] + 1)
        if p[0] == "new":
            return self.heap_field(p[1], p[2])
        return None

    def imm_store(self, off: int, before: Any = None) -> tuple | None:
        """The constant a ``MOV [stack slot], imm`` leaves at stack offset ``off`` (the last one before the address
        ``before``). The decompiler drops such a store when the address of the slot only goes to a call whose
        signature it does not know, so the instructions are read."""
        if self._imm is None:
            self._imm = {}
            prog = self.hf.getFunction().getProgram()
            it = prog.getListing().getInstructions(self.hf.getFunction().getBody(), True)
            while it.hasNext():
                ins = it.next()
                if str(ins.getMnemonicString()) != "MOV" or ins.getNumOperands() != 2:
                    continue
                objs = ins.getOpObjects(1)
                if len(objs) != 1 or not hasattr(objs[0], "getUnsignedValue"):
                    continue
                for ref in ins.getReferencesFrom():
                    if ref.isStackReference() and ref.getOperandIndex() == 0:
                        self._imm.setdefault(int(ref.getStackOffset()), []).append(
                            (ins.getAddress(), int(objs[0].getUnsignedValue())))
        got = [(a, v) for a, v in self._imm.get(off, []) if before is None or a.compareTo(before) < 0]
        if not got:
            return None
        if before is None:
            vals = {v for _a, v in got}
            return ("const", vals.pop()) if len(vals) == 1 else None
        return ("const", max(got, key=lambda t: t[0].getOffset())[1])

    def slot_value(self, op: Any, depth: int = 0) -> tuple | None:
        """The value a store-like op leaves in a stack slot: a COPY or STORE gives its source, an INDIRECT (a call
        that may have touched the slot) is looked through, a MULTIEQUAL needs equal inputs."""
        if depth > 14:
            return None
        m = op.getMnemonic()
        if m == "STORE":
            return self.value(op.getInput(2), depth + 1)
        if m == "COPY":
            return self.value(op.getInput(0), depth + 1)
        if m == "INDIRECT":
            d = op.getInput(0).getDef()
            return self.slot_value(d, depth + 1) if d is not None else None
        if m == "MULTIEQUAL":
            vals = set()
            for k in range(op.getNumInputs()):
                d = op.getInput(k).getDef()
                vals.add(self.slot_value(d, depth + 1) if d is not None else None)
            vals -= {("const", 0)}
            return vals.pop() if len(vals) == 1 and None not in vals else None
        return self.value(op.getOutput(), depth + 1)       # PTRSUB (a function address), CAST, ...

    def heap_field(self, new_id: int, off: int) -> tuple | None:
        vals = set()
        for p in self.ops:
            if p.getMnemonic() != "STORE":
                continue
            ptr = self.value(p.getInput(1))
            if ptr is not None and ptr[0] == "new" and ptr[1] == new_id and ptr[2] == off:
                vals.add(self.value(p.getInput(2)))
        return vals.pop() if len(vals) == 1 and None not in vals else None


class _Connects:
    def __init__(self, program: Any, di: Any, timeout: int, imports: dict[int, str] | None = None) -> None:
        self.program, self.di, self.timeout = program, di, timeout
        self.imports = imports or {}        # {import slot address: Class::name} from the PE import table
        self.fm = program.getFunctionManager()
        self.rm = program.getReferenceManager()
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.flows: dict[int, _Flow | None] = {}
        self.sigcache: dict[int, dict[str, Any]] = {}
        self.stats = {"decompiled": 0, "failed": 0}
        self.psize = int(program.getDefaultPointerSize())

    def addr(self, a: int) -> Any:
        return self.space.getAddress(a)

    def flow(self, entry: int) -> _Flow | None:
        if entry in self.flows:
            return self.flows[entry]
        fl = None
        f = self.fm.getFunctionAt(self.addr(entry))
        if f is not None and len(self.flows) < MAX_FLOWS:
            try:
                from ghidra.util.task import TaskMonitor  # type: ignore
                r = self.di.decompileFunction(f, self.timeout, TaskMonitor.DUMMY)
                if r.decompileCompleted() and r.getHighFunction() is not None:
                    fl = _Flow(r.getHighFunction())
                    self.stats["decompiled"] += 1
                else:
                    self.stats["failed"] += 1
            except Exception:  # noqa: BLE001
                self.stats["failed"] += 1
        self.flows[entry] = fl
        return fl

    def callers(self, entry: int) -> list[tuple[int, int]]:
        """(caller entry, call address) for calls and tail jumps to the function or its thunks."""
        f = self.fm.getFunctionAt(self.addr(entry))
        if f is None:
            return []
        targets = [f.getEntryPoint()]
        for a in f.getFunctionThunkAddresses(True) or []:
            targets.append(a)
        out: list[tuple[int, int]] = []
        for t in targets:
            for ref in self.rm.getReferencesTo(t):
                rt = ref.getReferenceType()
                if not (rt.isCall() or rt.isJump()):
                    continue
                frm = ref.getFromAddress()
                cf = self.fm.getFunctionContaining(frm)
                if cf is not None and cf.getEntryPoint() != f.getEntryPoint():
                    out.append((S.addr_int(cf.getEntryPoint()), S.addr_int(frm)))
        return sorted(set(out))

    def import_name(self, slot: int) -> str:
        """``Class::name`` of the import behind the pointer slot ``slot`` ("" when it holds no import)."""
        if slot in self.imports:
            return self.imports[slot]
        for ref in self.rm.getReferencesFrom(self.addr(slot)):
            if ref.isExternalReference():
                loc = ref.getExternalLocation()
                sym = loc.getSymbol() if loc is not None else None
                full = str(sym.getName(True)) if sym is not None else ""
                parts = full.split("::") if full else ([str(loc.getLabel())] if loc is not None else [])
                if parts and parts[0].upper().endswith(".DLL"):
                    parts = parts[1:]
                return "::".join(parts)
        return ""

    def target(self, v: tuple) -> dict[str, Any]:
        """A member pointer as a function: ``{"addr"}`` of the program function (thunks followed) or
        ``{"addr", "ext": "Class::name"}`` for an import (``("mem", slot)``: the import slot was read)."""
        if v[0] == "mem":
            name = self.import_name(v[1])
            return {"addr": v[1], "ext": name} if name else {"addr": v[1]}
        a = v[1]
        if a & 1 and a < VTABLE_MAX:       # Itanium: a virtual member pointer is the vtable offset plus one
            return {"virtual": a - 1}
        f = self.fm.getFunctionAt(self.addr(a)) or self.fm.getFunctionContaining(self.addr(a))
        if f is None:
            return {"addr": a}
        for _ in range(3):
            if not f.isThunk():
                break
            t = f.getThunkedFunction(False)
            if t is None:
                break
            f = t
        if f.isExternal():
            parts = str(f.getParentNamespace().getName(True)).split("::")
            if parts and parts[0].upper().endswith(".DLL"):
                parts = parts[1:]
            return {"addr": a, "ext": "::".join([*parts, str(f.getName())])}
        return {"addr": S.addr_int(f.getEntryPoint())}

    def callee_name(self, call: Any) -> str:
        """``Class::name`` of the function a CALL op calls (thunks followed; imports by their slot)."""
        callee = call.getInput(0)
        if callee is None:
            return ""
        a = callee.getAddress()
        f = self.fm.getFunctionAt(a)
        for _ in range(3):
            if f is None or not f.isThunk():
                break
            t = f.getThunkedFunction(False)
            if t is None:
                break
            f = t
        if f is not None:
            return str(f.getParentNamespace().getName(True)) + "::" + str(f.getName())
        return self.import_name(int(a.getOffset()))

    def is_connect_impl(self, call: Any) -> bool:
        return self.callee_name(call).endswith("QObject::connectImpl")

    def signal_index(self, entry: int) -> dict[str, Any]:
        """``{meta, idx}`` of a moc signal function: its call of ``QMetaObject::activate(this, &meta, idx, argv)``."""
        if entry in self.sigcache:
            return self.sigcache[entry]
        res: dict[str, Any] = {}
        fl = self.flow(entry)
        if fl is not None:
            for c in fl.calls():
                callee = c.getInput(0)
                if callee is None:
                    continue
                f = self.fm.getFunctionAt(callee.getAddress())
                name = (str(f.getParentNamespace().getName(True)) + "::" + str(f.getName())) if f is not None                     else self.import_name(int(callee.getAddress().getOffset()))
                if name.endswith("QMetaObject::activate"):
                    m, i = fl.value(c.getInput(2)), fl.value(c.getInput(3))
                    if m and i and m[0] == "const" and i[0] == "const":
                        res = {"meta": m[1], "idx": i[1]}
                        break
        self.sigcache[entry] = res
        return res

    def solve(self, fn: int, site: int) -> tuple[list[dict[str, Any]], str]:
        fl = self.flow(fn)
        if fl is None:
            return [], "no_decompile"
        call = fl.call_at(self.addr(site))
        if call is None or call.getNumInputs() < 7:
            return [], "no_call"
        # the function returns QMetaObject::Connection by value: input 1 is the result pointer
        sig = fl.deref(fl.value(call.getInput(3)), 0, self.addr(site))
        obj = fl.value(call.getInput(6))
        impl = slot = None
        if obj is not None and obj[0] == "new":
            # QSlotObjectBase: int m_ref, then m_impl (at one pointer), then the member pointer / functor
            impl = fl.heap_field(obj[1], self.psize)
            slot = fl.heap_field(obj[1], 2 * self.psize)
        if slot is None:
            slot = fl.deref(fl.value(call.getInput(5)), 0, self.addr(site))
        ncallers = len(self.callers(fn)) if sig is None or sig[0] == "param" or (slot and slot[0] == "param") else -1
        self.last = f"sig={sig} slot={slot} impl={impl} callers={ncallers}"
        out: list[dict[str, Any]] = []
        self._chase(fn, site, sig, slot, impl, MAX_DEPTH, out, frozenset())
        status = "ok" if out else ("no_callers" if ncallers == 0 else "unresolved")
        self.stats[status] = self.stats.get(status, 0) + 1
        return out, status

    def _chase(self, fn: int, site: int, sig, slot, impl, depth: int, out: list, seen: frozenset,
               origin: int | None = None) -> None:
        if sig is not None and sig[0] in ("const", "mem") and slot is not None and slot[0] == "param"                 and depth > 0 and fn not in seen:
            # the signal is known, the slot is a parameter (a wrapper): the callers hold the slot
            n = len(out)
            for cfn, csite in self.callers(fn)[:MAX_CALLERS]:
                cf = self.flow(cfn)
                c = cf.call_at(self.addr(csite)) if cf is not None else None
                if c is not None:
                    self._chase(cfn, csite, self._lift(cf, c, sig), self._lift(cf, c, slot), impl, depth - 1, out,
                                seen | {fn}, origin if origin is not None else site)
            if len(out) > n:
                return
        if sig is not None and sig[0] in ("const", "mem"):
            sg = self.target(sig)
            if sig[0] == "mem" and "ext" not in sg:
                return                                  # the content of a global that is no import
            r: dict[str, Any] = {"fn": fn, "site": site, "signal": sg}
            if origin is not None:
                r["origin"] = origin
            if slot is not None and slot[0] in ("const", "mem"):
                r["slot"] = self.target(slot)
                r["slot"]["kind"] = "pmf"
            elif impl is not None:
                r["slot"] = {"addr": impl[1], "kind": "functor"}
            out.append(r)
            return
        if depth <= 0 or fn in seen or sig is None or sig[0] != "param":
            return
        seen = seen | {fn}
        for cfn, csite in self.callers(fn)[:MAX_CALLERS]:
            cf = self.flow(cfn)
            if cf is None:
                continue
            c = cf.call_at(self.addr(csite))
            if c is None:
                continue
            self._chase(cfn, csite, self._lift(cf, c, sig), self._lift(cf, c, slot), impl, depth - 1, out, seen,
                        origin if origin is not None else site)

    @staticmethod
    def _lift(cf: _Flow, call: Any, v: tuple | None) -> tuple | None:
        """The value ``v`` (in terms of the callee's parameters) in the caller ``cf``, at the call ``call``."""
        if v is None or v[0] != "param":
            return v
        j, d = v[1], v[2]
        if call.getNumInputs() <= j + 1:
            return None
        w = cf.value(call.getInput(j + 1))
        for _ in range(d):
            w = cf.deref(w, 0, call.getSeqnum().getTarget())
        return w


CONNECT_IMPL_PARAMS = 9      # sret, sender, signal, receiver, slot, slot object, type, types, sender metaobject


def _fix_connect_signatures(e: Any) -> int:
    """Give the imported ``QObject::connectImpl`` a nine pointer signature when Ghidra left it without one (an
    Itanium name that does not demangle, or a MinGW call through a register): without it the decompiler shows
    the call without arguments. Idempotent; returns the number of functions changed."""
    from ghidra.program.model.data import PointerDataType, VoidDataType  # type: ignore
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from java.util import ArrayList  # type: ignore

    program = e.program
    todo = []
    for f in program.getFunctionManager().getExternalFunctions():
        if str(f.getName()) == "connectImpl" and str(f.getParentNamespace().getName(True)).endswith("QObject")                 and f.getParameterCount() < CONNECT_IMPL_PARAMS:
            todo.append(f)
    if not todo:
        return 0
    conv = "__cdecl" if program.getDefaultPointerSize() == 4 else Function.DEFAULT_CALLING_CONVENTION_STRING
    with e.fg, e.lock:
        check_open(e)
        tx = program.startTransaction("airlock qt connectImpl signature")
        ok = False
        try:
            for f in todo:
                vp = PointerDataType(VoidDataType.dataType)
                ps = ArrayList()
                for i in range(CONNECT_IMPL_PARAMS):
                    ps.add(ParameterImpl(f"p{i}", vp, program))
                f.updateFunction(conv, ReturnParameterImpl(VoidDataType.dataType, program), ps,
                                 Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.ANALYSIS)
            ok = True
        finally:
            program.endTransaction(tx, ok)
        dispose_decomp(e)
        e.epoch += 1
        S.require_project().save(program)
    return len(todo)


@op("qt_connects")
@guarded
def qt_connects(args: dict[str, Any]) -> dict[str, Any]:
    """qt_connects(program, sites=[{fn, site}], timeout=30): resolve the signal and the slot of the calls of
    ``QObject::connectImpl`` at ``site`` (inside the function ``fn``). A site that is no call (the compiler loaded
    the import into a register once and calls it from there) stands for every ``connectImpl`` call of ``fn``.
    Result {"results": [{fn, site, signal, slot}], "expanded": {site: [call address]}, "unresolved": [site],
    "secs", "stats"}; ``signal`` / ``slot`` are {addr, ext?, kind?, meta?, idx?, virtual?}."""
    e = S.ready_entry(args.get("program"))
    sites = args.get("sites")
    if not isinstance(sites, list) or len(sites) > MAX_SITES:
        raise WorkerError("bad_args", f"sites must be a list of at most {MAX_SITES} entries")
    timeout = int(args.get("timeout") or DECOMPILE_TIMEOUT_S)
    t0 = time.monotonic()
    fixed = 0
    if sites:
        try:
            fixed = _fix_connect_signatures(e)
        except Exception:  # noqa: BLE001  without it only the register calls stay unresolved
            fixed = -1
    results: list[dict[str, Any]] = []
    unresolved: list[int] = []
    expanded: dict[str, list[int]] = {}
    dbg: list[str] = []
    with S.POOL.foreground(), e.fg, e.lock.read():
        check_open(e)
        imports = {int(k): str(v) for k, v in (args.get("imports") or {}).items()}
        cx = _Connects(e.program, _decomp(e), timeout, imports)
        done: set[tuple[int, int]] = set()
        for s in sites:
            fn, site = int(s["fn"]), int(s["site"])
            todo = [site]
            fl = cx.flow(fn)
            if fl is not None and fl.call_at(cx.addr(site)) is None:
                todo = sorted({S.addr_int(c.getSeqnum().getTarget()) for c in fl.calls() if cx.is_connect_impl(c)})
                expanded[str(site)] = todo
            for call in todo:
                if (fn, call) in done:
                    continue
                done.add((fn, call))
                try:
                    got, _status = cx.solve(fn, call)
                except Exception:  # noqa: BLE001  one site must not stop the others
                    got = []
                if not got:
                    unresolved.append(call)
                    if args.get("debug"):
                        dbg.append(f"{call:#x} fn {fn:#x} {getattr(cx, 'last', '')}")
                for r in got:
                    if r["signal"].get("ext") is None and "addr" in r["signal"]:
                        r["signal"].update(cx.signal_index(r["signal"]["addr"]))
                    results.append(r)
    return {"results": results, "expanded": expanded, "unresolved": unresolved,
            "secs": round(time.monotonic() - t0, 1), "stats": {**cx.stats, "signatures": fixed},
            "debug": dbg[:80]}
