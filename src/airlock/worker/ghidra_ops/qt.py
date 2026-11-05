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
