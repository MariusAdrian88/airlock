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
from typing import Any, Callable

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from .decompile import _decomp, _resolve_function, check_open, open_decompiler
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
SITE_BUDGET_S = 40           # time one connect site (with its chase up the callers) may take
MAX_NEST = 60               # nesting of value() calls (they also recurse through stores)
RETRY_FACTOR = 6          # a decompile that timed out is tried once more with this many times the timeout
VTABLE_MAX = 0x4000        # an odd member pointer below this is an Itanium virtual one (vtable offset + 1)
PREFETCH_THREADS = 4       # decompilers that decompile the functions with call sites at once (within the pool budget)
RECV_DEPTH = 3            # steps (callers, returns, fields) to find the class of a receiver
_PASS = frozenset({"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "INDIRECT"})


def _signed(v: int, size: int = 8) -> int:
    """``v`` as a signed number of ``size`` bytes (constants of a 32-bit program are 4 bytes wide)."""
    bits = max(1, size) * 8
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >= 1 << (bits - 1) else v


class _Budget(Exception):
    """The time for one connect site is used up (a pathological function): the site stays unresolved."""

    until = 0.0            # time.monotonic() deadline of the current site, 0 = none

    @classmethod
    def start(cls) -> None:
        cls.until = time.monotonic() + SITE_BUDGET_S


class _Flow:
    """Symbolic values of one decompiled function: ``("const", a)``, ``("param", i, d)`` (parameter ``i`` read
    through ``d`` pointers), ``("stack", off)`` (address of a stack slot) or ``("new", id, off)`` (a call result
    plus an offset)."""

    def __init__(self, hf: Any) -> None:
        self.hf = hf
        self._imm: dict[int, list[tuple[Any, int]]] | None = None
        self.psize = int(hf.getFunction().getProgram().getDefaultPointerSize())
        self._nest = 0
        self._cuts = 0
        self._smemo: dict[tuple, tuple | None] = {}
        self._memo: dict[int, tuple | None] = {}
        self._heap: dict[tuple[int, int], tuple | None] = {}
        self.ops = list(hf.getPcodeOps())
        self._stack: dict[int, list[Any]] = {}      # stack offset -> ops that store there (value = input 0 / 2)
        self._late: list[Any] = []
        for p in self.ops:
            out = p.getOutput()
            if out is not None and out.getAddress().isStackAddress()                     and p.getMnemonic() in ("COPY", "INDIRECT", "MULTIEQUAL", "PTRSUB", "CAST", "PIECE"):
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
        """Symbolic value of ``vn``. ``depth`` bounds one chain of definitions; ``_nest`` bounds the whole
        recursion, which also runs through ``deref`` and ``heap_field`` (a cycle of stores would not end)."""
        if vn is None:
            return None
        if _Budget.until and time.monotonic() > _Budget.until:
            raise _Budget("site budget used up")
        if self._nest > MAX_NEST:
            self._cuts += 1
            return None
        try:
            key = int(vn.getUniqueId())
        except Exception:  # noqa: BLE001
            key = None
        if key is not None and key in self._memo:
            return self._memo[key]
        self._nest += 1
        try:
            res = self._value(vn, depth)
        finally:
            self._nest -= 1
        if key is not None:         # also a result a limit cut short: unknown stays unknown, and the walk is not repeated
            self._memo[key] = res
        return res

    def _value(self, vn: Any, depth: int) -> tuple | None:
        if vn is None:
            return None
        if depth > 14:
            self._cuts += 1
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
        that may have touched the slot) is looked through, a MULTIEQUAL needs equal inputs. Memoised: in a huge
        function the chains of MULTIEQUAL ops would otherwise be walked again and again."""
        if depth > 14:
            self._cuts += 1
            return None
        sq = op.getSeqnum()
        key = (int(sq.getTarget().getOffset()), int(sq.getTime()), str(op.getMnemonic()))
        if key in self._smemo:
            return self._smemo[key]
        self._smemo[key] = None             # a cycle of phi ops ends here (unknown)
        res = self._slot_value(op, depth)
        self._smemo[key] = res
        return res

    def _slot_value(self, op: Any, depth: int) -> tuple | None:
        m = op.getMnemonic()
        if m == "STORE":
            return self.value(op.getInput(2), depth + 1)
        if m == "COPY":
            return self.value(op.getInput(0), depth + 1)
        if m == "PIECE":            # a member pointer (two words) stored as one 16 byte value: the low part is at the slot
            return self.value(op.getInput(1), depth + 1)
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

    def field(self, vn: Any, depth: int = 0) -> tuple | None:
        """``vn`` as a chain of field loads from a parameter: ``("p", i)`` for parameter ``i``, ``("ld", base,
        off)`` for ``*(base + off)``. None for anything else. Used for receivers ``value`` cannot express
        (``this->ui->button``)."""
        if vn is None or depth > 8 or vn.isConstant():
            return None
        d = vn.getDef()
        if d is None:
            i = self.param_index(vn)
            return ("p", i) if i is not None else None
        m = d.getMnemonic()
        if m in _PASS:
            return self.field(d.getInput(0), depth + 1)
        if m == "LOAD":
            loc = self.location(d.getInput(1), depth + 1)
            return ("ld", *loc) if loc is not None else None
        return None

    def location(self, vn: Any, depth: int = 0) -> tuple | None:
        """``(base, off)`` of a pointer ``base + off`` with ``base`` a ``field`` chain, None when unknown."""
        if vn is None or depth > 8:
            return None
        d = vn.getDef()
        if d is not None and d.getMnemonic() in ("INT_ADD", "PTRSUB", "PTRADD") and d.getInput(1).isConstant():
            b = d.getInput(1)
            off = _signed(int(b.getOffset()), b.getSize()) * (int(d.getInput(2).getOffset()) if d.getMnemonic() == "PTRADD" else 1)
            inner = self.location(d.getInput(0), depth + 1)
            return (inner[0], inner[1] + off) if inner is not None else None
        if d is not None and d.getMnemonic() in _PASS:
            return self.location(d.getInput(0), depth + 1)
        base = self.field(vn, depth + 1)
        return (base, 0) if base is not None else None

    def field_stores(self, fld: tuple) -> list[tuple[Any, tuple | None]]:
        """(STORE op, stored value) for every store into the field ``fld`` (a ``("ld", base, off)`` chain)."""
        out = []
        for p in self.ops:
            if p.getMnemonic() == "STORE":
                loc = self.location(p.getInput(1))
                if loc is not None and ("ld", *loc) == fld:
                    out.append((p, self.value(p.getInput(2))))
        return out

    def heap_field(self, new_id: int, off: int) -> tuple | None:
        if (new_id, off) in self._heap:
            return self._heap[(new_id, off)]
        self._heap[(new_id, off)] = None            # a cycle through this field ends here
        res = self._heap_field(new_id, off)
        self._heap[(new_id, off)] = res
        return res

    def _heap_field(self, new_id: int, off: int) -> tuple | None:
        vals = set()
        for p in self.ops:
            if p.getMnemonic() != "STORE":
                continue
            ptr = self.value(p.getInput(1))
            if ptr is not None and ptr[0] == "new" and ptr[1] == new_id and ptr[2] == off:
                vals.add(self.value(p.getInput(2)))
        return vals.pop() if len(vals) == 1 and None not in vals else None


class _Connects:
    def __init__(self, program: Any, di: Any, timeout: int, imports: dict[int, str] | None = None,
                 vtables: dict[int, str] | None = None, fnclass: dict[int, str] | None = None,
                 primary: dict[str, int] | None = None, allvts: dict[int, str] | None = None,
                 parents: dict[str, str] | None = None) -> None:
        self.program, self.di, self.timeout = program, di, timeout
        self.imports = imports or {}        # {import slot address: Class::name} from the PE import table
        self.vtables = vtables or {}        # {vtable address point: class} (RTTI, or found through metaObject())
        self.fnclass = fnclass or {}        # {function entry: class} of methods and virtual functions
        self.primary = primary or {}        # {class: address point of its own vtable} where that is unambiguous
        self.allvts = allvts or dict(self.vtables)   # also the vtables of classes others derive from
        self.parents = parents or {}        # {class of the program: its superclass} (Qt metaobjects, RTTI)
        self._ctor: dict[int, int] = {}
        self._recv: dict[tuple, int | str] = {}
        self._lib: dict[tuple[str, int], dict[str, Any] | None] = {}
        self._kids: dict[str, list[int]] | None = None
        self._pre: dict[int, Any] = {}      # HighFunctions decompiled ahead by ``prefetch``
        self.fm = program.getFunctionManager()
        self.rm = program.getReferenceManager()
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.flows: dict[int, _Flow | None] = {}
        self.sigcache: dict[int, dict[str, Any]] = {}
        self.stats = {"decompiled": 0, "failed": 0}
        self.psize = int(program.getDefaultPointerSize())

    def addr(self, a: int) -> Any:
        return self.space.getAddress(a)

    def _decompile(self, di: Any, f: Any) -> Any:
        """The HighFunction of ``f`` (None when the decompile fails); a timeout is tried once more, longer."""
        from ghidra.util.task import TaskMonitor  # type: ignore
        r = di.decompileFunction(f, self.timeout, TaskMonitor.DUMMY)
        if not r.decompileCompleted() and r.isTimedOut():      # a huge init function: one longer try
            r = di.decompileFunction(f, self.timeout * RETRY_FACTOR, TaskMonitor.DUMMY)
        return r.getHighFunction() if r.decompileCompleted() else None

    def prefetch(self, entries: list[int], threads: int, open_di: Callable[[], Any]) -> int:
        """Decompile ``entries`` (the functions with call sites) on ``threads`` decompilers at once: the
        decompiles are most of the time of the op, and the huge functions would otherwise run one after the
        other. ``flow`` then builds on the stored results. Returns the number decompiled."""
        todo = [e for e in dict.fromkeys(entries) if e not in self.flows and e not in self._pre][:MAX_FLOWS]
        if threads < 2 or len(todo) < 2:
            return 0
        import queue
        import threading
        q: queue.SimpleQueue = queue.SimpleQueue()
        for e in todo:
            q.put(e)
        lock = threading.Lock()

        def run() -> None:
            try:
                di = open_di()
            except Exception:  # noqa: BLE001  the rest is decompiled one by one by flow()
                return
            try:
                while True:
                    try:
                        e = q.get_nowait()
                    except queue.Empty:
                        return
                    f = self.fm.getFunctionAt(self.addr(e))
                    try:
                        hf = self._decompile(di, f) if f is not None else None
                    except Exception:  # noqa: BLE001
                        hf = None
                    with lock:
                        self._pre[e] = hf
            finally:
                di.dispose()

        ts = [threading.Thread(target=run, daemon=True, name=f"airlock-qt-{i}") for i in range(min(threads, len(todo)))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return sum(1 for e in todo if self._pre.get(e) is not None)

    def flow(self, entry: int) -> _Flow | None:
        if entry in self.flows:
            return self.flows[entry]
        fl = None
        f = self.fm.getFunctionAt(self.addr(entry))
        if f is not None and len(self.flows) < MAX_FLOWS:
            try:
                hf = self._pre.pop(entry) if entry in self._pre else self._decompile(self.di, f)
                if hf is not None:
                    _Budget.start()
                    fl = _Flow(hf)
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

    def uncalled(self, entry: int) -> bool:
        """True when nothing refers to the function but the unwind table: a template instance the linker kept
        and nobody calls (no call, no jump, no stored address)."""
        f = self.fm.getFunctionAt(self.addr(entry))
        if f is None:
            return False
        mem = self.program.getMemory()
        for t in [f.getEntryPoint(), *(f.getFunctionThunkAddresses(True) or [])]:
            for ref in self.rm.getReferencesTo(t):
                if ref.getReferenceType().isCall() or ref.getReferenceType().isJump():
                    return False
                blk = mem.getBlock(ref.getFromAddress())
                if blk is None:
                    return False
                if str(blk.getName()).lower() != ".pdata" and not self._unwind_data(ref.getFromAddress()):
                    return False
        return True

    def _unwind_data(self, a: Any) -> bool:
        """True when ``a`` lies in unwind data (a chained ``UNWIND_INFO`` in ``.rdata`` names its function too)."""
        try:
            d = self.program.getListing().getDataContaining(a)
            name = str(d.getDataType().getName()) if d is not None else ""
        except Exception:  # noqa: BLE001
            return False
        return "UnwindInfo" in name or "RUNTIME_FUNCTION" in name

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

    def vcall_offset(self, a: int) -> int | None:
        """Vtable byte offset of an MSVC vcall thunk at ``a`` (``mov rax,[rcx]; jmp [rax+off]``, 32-bit
        ``mov eax,[ecx]; jmp [eax+off]``), None for any other code."""
        mem = self.program.getMemory()
        try:
            at = self.addr(a)
            b = bytes(int(mem.getByte(at.add(i))) & 0xFF for i in range(10))
        except Exception:  # noqa: BLE001  unreadable memory
            return None
        if b[:3] == bytes((0x48, 0x8B, 0x01)):
            b = b[3:]
        elif b[:2] == bytes((0x8B, 0x01)):
            b = b[2:]
        else:
            return None
        if b[:2] == bytes((0xFF, 0x60)):
            return b[2]
        if b[:2] == bytes((0xFF, 0xA0)):
            return int.from_bytes(b[2:6], "little")
        if b[:2] == bytes((0xFF, 0x20)):
            return 0
        return None

    @staticmethod
    def _key(p: Any) -> tuple[int, int]:
        sq = p.getSeqnum()
        return int(sq.getTarget().getOffset()), int(sq.getTime())

    def ctor_vt(self, entry: int, exact: bool = False) -> int:
        """Vtable the function at ``entry`` stores into its ``this`` (a constructor): the last constant stored
        at ``*this`` in address order (the most derived class), when it is a known vtable. ``exact``: any known
        vtable (the object is of exactly this class: ``new``), else only those of classes nobody derives from
        (``this`` of a constructor may be a base part of a derived object). 0 when there is none."""
        if (entry, exact) in self._ctor:
            return self._ctor[(entry, exact)]
        table = self.allvts if exact else self.vtables
        vt = 0
        fl = self.flow(entry) if table else None
        if fl is not None:
            best = None
            for p in fl.ops:
                if p.getMnemonic() != "STORE":
                    continue
                ptr, val = fl.value(p.getInput(1)), fl.value(p.getInput(2))
                if ptr == ("param", 0, 0) and val is not None and val[0] == "const":
                    key = self._key(p)
                    if best is None or key > best[0]:
                        best = (key, val[1])
            vt = best[1] if best and best[1] in table else 0
        self._ctor[(entry, exact)] = vt
        return vt

    def _resolved(self, a: Any) -> Any:
        """The function at address ``a`` with thunks followed (None when there is none)."""
        f = self.fm.getFunctionAt(a) if a is not None else None
        for _ in range(3):
            if f is None or not f.isThunk():
                break
            t = f.getThunkedFunction(False)
            if t is None:
                break
            f = t
        return f

    def recv_vt(self, fn: int, recv: tuple | None, depth: int = 0) -> int | str:
        """Class of the receiver ``recv`` of a connect inside ``fn``: the address point of a program vtable, or
        the name of a library class (a str). 0 when it is not known for sure. Sources: ``this`` of a constructor
        or of a known method; a parameter all callers give objects of one class; an object ``new``-ed here
        (inlined constructor, constructor call, MSVC import ``Class::vftable`` stored); the result of a call
        whose returns are all of one class; a field this function stores such an object into."""
        if recv is None or depth > RECV_DEPTH:
            return 0
        key = (fn, recv)
        if key in self._recv:
            return self._recv[key]
        self._recv[key] = 0             # a cycle through the callers ends here (unknown)
        try:
            res = self._recv_vt(fn, recv, depth)
        except _Budget:
            res = 0
        self._recv[key] = res
        return res

    def _recv_vt(self, fn: int, recv: tuple, depth: int) -> int | str:
        if recv[0] == "param" and recv[2] == 0:
            if recv[1] == 0:
                vt = self.ctor_vt(fn) or self.primary.get(self.fnclass.get(fn, ""), 0)
                if vt:
                    return vt
            return self.caller_vt(fn, recv, depth)
        fl = self.flow(fn)
        if fl is None:
            return 0
        if (recv[0] == "new" and recv[2] == 0) or recv[0] == "stack":       # a heap or a stack object
            return self.new_vt(fl, fn, recv, depth)
        if recv[0] == "field":
            got = {self.recv_vt(fn, v, depth + 1) for _p, v in fl.field_stores(recv[1])}
            return got.pop() if len(got) == 1 else 0
        return 0

    def caller_vt(self, fn: int, recv: tuple, depth: int) -> int | str:
        """The class every caller of ``fn`` passes in the parameter ``recv`` (thunks are looked through: their
        callers are callers of ``fn`` too). 0 when a caller is unknown or two disagree."""
        got: set = set()
        cs = self.callers(fn)
        if not cs or len(cs) > MAX_CALLERS:
            return 0
        for cfn, csite in cs:
            f = self.fm.getFunctionAt(self.addr(cfn))
            if f is not None and f.isThunk():
                continue
            cf = self.flow(cfn)
            c = cf.call_at(self.addr(csite)) if cf is not None else None
            if c is None:
                return 0
            got.add(self.recv_vt(cfn, self._lift(cf, c, recv), depth + 1))
        return got.pop() if len(got) == 1 else 0

    def new_vt(self, fl: Any, fn: int, recv: tuple, depth: int) -> int | str:
        """Class of the object ``recv`` (a call result) in ``fn``: the last of the vtable stores at its start, the
        constructors called on it and the MSVC ``Class::vftable`` import stores decides (an unknown one last:
        unknown). Without any, the class every return of the called function gives. A stack object (``("stack",
        off)``) needs one class from all of them."""
        last = None
        seen: set = set()
        for p in fl.ops:
            m = p.getMnemonic()
            if m == "STORE":
                if fl.value(p.getInput(1)) != recv:
                    continue
                v = fl.value(p.getInput(2))
                if v is None or v[0] not in ("const", "mem"):
                    continue
                if v[0] == "const":
                    got: int | str = v[1] if v[1] in self.allvts else 0
                else:
                    name = self.import_name(v[1])
                    got = name[:-len("::vftable")] if name.endswith("::vftable") else 0
            elif m in ("CALL", "CALLIND") and p.getNumInputs() > 1 and fl.value(p.getInput(1)) == recv:
                f = self._resolved(p.getInput(0).getAddress() if p.getInput(0) is not None else None)
                if f is None:
                    continue
                if f.isExternal():
                    parts = [*str(f.getParentNamespace().getName(True)).split("::"), str(f.getName())]
                    if parts and parts[0].upper().endswith(".DLL"):
                        parts = parts[1:]
                    if len(parts) < 2 or parts[-1] != parts[-2]:
                        continue                # a method call, no constructor
                    got = "::".join(parts[:-1])
                else:
                    got = self.ctor_vt(S.addr_int(f.getEntryPoint()), True)
                    if not got:
                        continue                # no constructor of a known class (a method, a setter)
            else:
                continue
            k = self._key(p)
            seen.add(got)
            if last is None or k > last[0]:
                last = (k, got)
        if recv[0] == "stack":          # a stack slot may hold several objects in turn: all must agree
            return seen.pop() if len(seen) == 1 else 0
        if last is not None:
            return last[1]
        for p in fl.ops:
            if recv[0] == "new" and p.getMnemonic() in ("CALL", "CALLIND") and self._key(p) == tuple(recv[1]):
                return self.return_vt(fl, fn, p, depth)
        return 0

    def return_vt(self, fl: Any, fn: int, call: Any, depth: int) -> int | str:
        """Class of what the function called by ``call`` (in ``fn``) returns: the same on every return. A return
        of a parameter is the argument of this call."""
        f = self._resolved(call.getInput(0).getAddress() if call.getInput(0) is not None else None)
        if f is None or f.isExternal():
            return 0
        entry = S.addr_int(f.getEntryPoint())
        cf = self.flow(entry)
        if cf is None:
            return 0
        got: set = set()
        for p in cf.ops:
            if p.getMnemonic() != "RETURN":
                continue
            if p.getNumInputs() < 2:
                return 0
            v = cf.value(p.getInput(1))
            if v is not None and v[0] == "param" and v[2] == 0:
                w = fl.value(call.getInput(v[1] + 1)) if call.getNumInputs() > v[1] + 1 else None
                got.add(self.recv_vt(fn, w, depth + 1))
            else:
                got.add(self.recv_vt(entry, v, depth + 1))
        return got.pop() if len(got) == 1 else 0

    def _vt_word(self, a: int) -> int | None:
        mem = self.program.getMemory()
        try:
            at = self.addr(a)
            return int(mem.getLong(at)) & 0xFFFFFFFFFFFFFFFF if self.psize == 8 else int(mem.getInt(at)) & 0xFFFFFFFF
        except Exception:  # noqa: BLE001
            return None

    def _is_code(self, w: int | None) -> bool:
        if not w:
            return False
        try:
            blk = self.program.getMemory().getBlock(self.addr(w))
        except Exception:  # noqa: BLE001
            return False
        return blk is not None and bool(blk.isExecute())

    def reaches(self, vt: int, off: int) -> bool:
        """True when the vtable at ``vt`` holds code pointers in every slot up to byte offset ``off``."""
        return off >= 0 and all(self._is_code(self._vt_word(vt + k)) for k in range(0, off + 1, self.psize))

    def lib_target(self, cls: str, off: int) -> dict[str, Any] | None:
        """``{"addr", "ext"}`` of the virtual at byte offset ``off`` of the library class ``cls``. A program class
        whose chain of program superclasses ends at ``cls`` inherits that slot unless it overrides it; an
        override is program code, an inherited slot is an import. All such import slots must agree."""
        if (cls, off) in self._lib:
            return self._lib[(cls, off)]
        if self._kids is None:
            own = set(self.allvts.values()) | set(self.parents)
            self._kids = {}
            for va, c in self.allvts.items():
                seen = set()
                while c in own and c not in seen:
                    seen.add(c)
                    c = self.parents.get(c, "")
                if c and c not in own:
                    self._kids.setdefault(c, []).append(va)
        names: dict[str, dict[str, Any]] = {}
        for va in self._kids.get(cls, []):
            if not self.reaches(va, off):
                continue
            w = self._vt_word(va + off)
            t = self.import_thunk(w) if w else None
            if t is None and w:
                f = self._resolved(self.addr(w))
                if f is not None and f.isExternal():
                    t = self.target(("const", w))
            if t is not None and t.get("ext") and "purecall" not in t["ext"] and "pure_virtual" not in t["ext"]:
                names.setdefault(t["ext"], t)
        res = next(iter(names.values())) if len(names) == 1 else None
        self._lib[(cls, off)] = res
        return res

    def import_thunk(self, w: int) -> dict[str, Any] | None:
        """``{"addr", "ext"}`` when the code at ``w`` is ``jmp [import slot]`` (a vtable slot of a class that
        inherits a library virtual keeps such a stub, Ghidra often has no function there), else None."""
        try:
            ins = self.program.getListing().getInstructionAt(self.addr(w))
            if ins is None or str(ins.getMnemonicString()) != "JMP":
                return None
            for ref in ins.getReferencesFrom():
                if ref.isMemoryReference():
                    name = self.import_name(int(ref.getToAddress().getOffset()))
                    if name:
                        return {"addr": w, "ext": name}
        except Exception:  # noqa: BLE001
            return None
        return None

    def virtual_target(self, vt: int, off: int) -> dict[str, Any] | None:
        """The function in the vtable at ``vt`` at byte offset ``off`` (thunks followed), None when not known."""
        if not vt or not self.reaches(vt, off):
            return None
        w = self._vt_word(vt + off)
        if w is None:
            return None
        if self.fm.getFunctionAt(self.addr(w)) is None:
            return self.import_thunk(w)
        t = self.target(("const", w))          # an inherited library function comes back as an import ("ext")
        if "virtual" in t or "pure_virtual" in t.get("ext", "") or "purecall" in t.get("ext", ""):
            return None                         # an abstract slot: the real object overrides it
        return t

    def target(self, v: tuple) -> dict[str, Any]:
        """A member pointer as a function: ``{"addr"}`` of the program function (thunks followed) or
        ``{"addr", "ext": "Class::name"}`` for an import (``("mem", slot)``: the import slot was read)."""
        if v[0] == "mem":
            name = self.import_name(v[1])
            return {"addr": v[1], "ext": name} if name else {"addr": v[1]}
        a = v[1]
        if a & 1 and a < VTABLE_MAX:       # Itanium: a virtual member pointer is the vtable offset plus one
            return {"virtual": a - 1}
        voff = self.vcall_offset(a)
        if voff is not None:            # MSVC: a virtual member pointer is the address of a vcall thunk
            return {"virtual": voff, "msvc": 1}
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
        if not f.isExternal():
            voff = self.vcall_offset(S.addr_int(f.getEntryPoint()))      # an incremental-link stub in front of the thunk
            if voff is not None:
                return {"virtual": voff, "msvc": 1}
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
        _Budget.start()
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
        _Budget.start()
        fl = self.flow(fn)
        if fl is None:
            return [], "no_decompile"
        call = fl.call_at(self.addr(site))
        if call is None or call.getNumInputs() < 7:
            return [], "no_call"
        # the function returns QMetaObject::Connection by value: input 1 is the result pointer
        sig = fl.deref(fl.value(call.getInput(3)), 0, self.addr(site))
        obj = fl.value(call.getInput(6))
        recv = fl.value(call.getInput(4))
        if recv is None:                # this->ui->button: a field, typed by the stores into it
            fld = fl.field(call.getInput(4))
            recv = ("field", fld) if fld is not None and fld[0] == "ld" else None
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
        self._chase(fn, site, sig, slot, impl, MAX_DEPTH, out, frozenset(), None, recv)
        status = "ok" if out else (("uncalled" if self.uncalled(fn) else "no_callers") if ncallers == 0 else "unresolved")
        self.stats[status] = self.stats.get(status, 0) + 1
        return out, status

    def _chase(self, fn: int, site: int, sig, slot, impl, depth: int, out: list, seen: frozenset,
               origin: int | None = None, recv: tuple | None = None) -> None:
        if sig is not None and sig[0] in ("const", "mem") and slot is not None and slot[0] == "param"                 and depth > 0 and fn not in seen:
            # the signal is known, the slot is a parameter (a wrapper): the callers hold the slot
            n = len(out)
            for cfn, csite in self.callers(fn)[:MAX_CALLERS]:
                cf = self.flow(cfn)
                c = cf.call_at(self.addr(csite)) if cf is not None else None
                if c is not None:
                    self._chase(cfn, csite, self._lift(cf, c, sig), self._lift(cf, c, slot), impl, depth - 1, out,
                                seen | {fn}, origin if origin is not None else site, self._lift(cf, c, recv))
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
                if "virtual" in r["slot"]:
                    off = r["slot"]["virtual"]
                    vt = self.recv_vt(fn, recv)
                    lib = isinstance(vt, str)
                    t = self.lib_target(vt, off) if lib else self.virtual_target(vt, off)
                    if t is not None:
                        r["slot"] = {**t, "kind": "pmf", "virt": off, "cls": vt if lib else self.allvts.get(vt, "")}
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
                        origin if origin is not None else site, self._lift(cf, c, recv))

    @staticmethod
    def _lift(cf: _Flow, call: Any, v: tuple | None) -> tuple | None:
        """The value ``v`` (in terms of the callee's parameters) in the caller ``cf``, at the call ``call``."""
        if v is None or v[0] == "field":
            return None                 # a field chain is in terms of the callee's parameters
        if v[0] != "param":
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
        with S.transaction(program, "airlock qt connectImpl signature"):
            for f in todo:
                vp = PointerDataType(VoidDataType.dataType)
                ps = ArrayList()
                for i in range(CONNECT_IMPL_PARAMS):
                    ps.add(ParameterImpl(f"p{i}", vp, program))
                f.updateFunction(conv, ReturnParameterImpl(VoidDataType.dataType, program), ps,
                                 Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.ANALYSIS)
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
    "uncalled": [site] (unresolved sites in a function nothing refers to),
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
    uncalled: list[int] = []
    expanded: dict[str, list[int]] = {}
    dbg: list[str] = []
    with S.POOL.foreground(), e.fg, e.lock.read():
        check_open(e)
        imports = {int(k): str(v) for k, v in (args.get("imports") or {}).items()}
        vts = {int(k): str(v) for k, v in (args.get("vtables") or {}).items()}
        fnc = {int(k): str(v) for k, v in (args.get("fnclass") or {}).items()}
        prim = {str(k): int(v) for k, v in (args.get("primary") or {}).items()}
        allv = {int(k): str(v) for k, v in (args.get("allvtables") or {}).items()} or None
        pars = {str(k): str(v) for k, v in (args.get("parents") or {}).items()}
        cx = _Connects(e.program, _decomp(e), timeout, imports, vts, fnc, prim, allv, pars)
        try:
            fns = list(dict.fromkeys(int(s["fn"]) for s in sites))
            ups = [c for fn in fns for c, _a in cx.callers(fn)[:MAX_CALLERS]]      # the chase reads the callers
            pre = cx.prefetch(fns + ups, min(PREFETCH_THREADS, S.POOL.total()), lambda: open_decompiler(e.program))
        except Exception:  # noqa: BLE001  flow() decompiles one by one
            pre = -1
        cx.stats["prefetched"] = pre
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
                    got, status = cx.solve(fn, call)
                except Exception:  # noqa: BLE001  one site must not stop the others
                    got, status = [], "error"
                if not got:
                    unresolved.append(call)
                    if status == "uncalled":
                        uncalled.append(call)
                    if args.get("debug"):
                        dbg.append(f"{call:#x} fn {fn:#x} {getattr(cx, 'last', '')}")
                for r in got:
                    if r["signal"].get("ext") is None and "addr" in r["signal"]:
                        try:
                            r["signal"].update(cx.signal_index(r["signal"]["addr"]))
                        except Exception:  # noqa: BLE001  the signal stays a function address
                            pass
                    results.append(r)
    return {"results": results, "expanded": expanded, "unresolved": unresolved, "uncalled": uncalled,
            "secs": round(time.monotonic() - t0, 1), "stats": {**cx.stats, "signatures": fixed},
            "debug": dbg[:3000]}
