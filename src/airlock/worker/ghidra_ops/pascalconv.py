"""Register-convention prototypes for 32-bit Pascal code (Delphi and Free Pascal i386).

The ``register`` convention passes the first three arguments in EAX, EDX, ECX (``Self`` of a method first), the
rest on the stack pushed left to right (the first one is the deepest), and the callee pops them (``RET n``).
Ghidra's Delphi compiler spec has the register part (``__register``) but lists the stack part in the wrong
order (``param_4`` is the last argument); a Free Pascal program gets the Visual Studio spec and its guessed
``__fastcall`` (ECX, EDX), so ``Self`` is lost and ``in_EAX`` / ``in_ECX`` appear. This pass gives such a
function its full prototype with custom storage: registers first, then the stack slots from the highest
offset down. Pure helpers first (testable with fakes), the Ghidra part below."""

from __future__ import annotations

from typing import Any, Iterable

REGS = ("EAX", "EDX", "ECX")
SCAN_LIMIT = 40          # instructions of the entry path
SITE_WINDOW = 12         # instructions before a call searched for loads of a register
MAX_SITES = 16           # callers examined per function
MAX_BODY = 4000         # bytes of a function body that the liveness pass examines
MAX_DEPTH = 6           # callee levels that the liveness pass follows
MAX_SLOTS = 32           # stack arguments of a register-convention function (words)


Node = tuple[frozenset[str], frozenset[str], tuple[int, ...]]     # (read, written, successors)


def live_regs(nodes: dict[int, Node], entry: int) -> int:
    """Register arguments of a function: ``nodes`` maps an instruction address to (registers read, registers
    written, successor addresses). The result is the position (1 to 3) of the last of EAX, EDX, ECX that is
    live at the entry (read on some path before it is written), 0 when none is. A call reads the registers
    its callee takes and writes all three."""
    want = set(REGS)
    live: dict[int, frozenset[str]] = {a: frozenset() for a in nodes}
    preds: dict[int, list[int]] = {}
    for a, (_rd, _wr, succ) in nodes.items():
        for t in succ:
            preds.setdefault(t, []).append(a)
    work = list(nodes)
    while work:
        a = work.pop()
        rd, wr, succ = nodes[a]
        out = frozenset().union(*(live.get(t, frozenset()) for t in succ)) if succ else frozenset()
        new = frozenset((set(rd) | (out - wr)) & want)
        if new != live[a]:
            live[a] = new
            work.extend(preds.get(a, ()))
    return max((REGS.index(r) + 1 for r in live.get(entry, ())), default=0)


def site_reg_count(sites: list[list[tuple[frozenset[str], frozenset[str]]]]) -> int:
    """Register arguments all callers load. A site is the (read, written) pairs of the instructions before the
    call, nearest first, ending at the previous call or branch. A register counts for a site when it is
    written there and not read later in the window (``MOV EAX, x; PUSH EAX`` is a stack argument). Every
    caller must load the register (the first caller alone is enough when it is the only one); a later
    register needs the earlier ones."""
    if not sites:
        return 0
    counts = []
    for seq in sites:
        loaded: set[str] = set()
        read_after: set[str] = set()        # nearest first: instructions nearer the call were seen already
        for rd, wr in seq:
            for r in REGS:
                if r in wr and r not in read_after:
                    loaded.add(r)
            read_after |= rd
            read_after -= wr
        counts.append(max((REGS.index(r) + 1 for r in loaded), default=0))
    return min(counts)


def stack_layout(slots: int, existing: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Stack arguments of a function that pops ``slots`` words: (offset, size) from the first argument (the
    highest offset) to the last. ``existing`` holds the (offset, size) of the stack parameters that Ghidra
    found; they keep their size (an 8-byte argument covers two slots); the gaps become word arguments.
    Offsets are those of the callee's frame (the first slot is at 4, behind the return address)."""
    taken: dict[int, int] = {}
    for off, size in sorted(existing):
        if off >= 4 and (off - 4) % 4 == 0 and size >= 1 and off + size - 4 <= 4 * slots \
                and not any(o < off + size and off < o + s for o, s in taken.items()):
            taken[off] = size
    out: list[tuple[int, int]] = []
    off = 4
    while off < 4 + 4 * slots:
        size = taken.get(off, 4)
        out.append((off, size))
        off += (size + 3) // 4 * 4
    out.reverse()
    return out


def wanted_layout(regs: int, slots: int, existing: list[tuple[int, int]]) -> tuple[tuple[str, ...], list[tuple[int, int]]]:
    """(registers, stack arguments) of the prototype."""
    return REGS[:regs], stack_layout(slots, existing)


# ── Ghidra part ──────────────────────────────────────────────────────────────

def _folded(objs: Iterable[Any], Register: Any) -> frozenset[str]:
    out = set()
    for o in objs:
        if isinstance(o, Register):
            n = str(o.getBaseRegister().getName()).upper()
            if n in REGS:
                out.add(n)
    return frozenset(out)


def _step(ins: Any, Register: Any) -> tuple[frozenset[str], frozenset[str]]:
    mn = str(ins.getMnemonicString()).upper()
    rd = _folded(ins.getInputObjects(), Register)
    wr = _folded(ins.getResultObjects(), Register)
    if mn in ("XOR", "SUB", "SBB") and ins.getNumOperands() == 2 and str(ins.getDefaultOperandRepresentation(0)) \
            == str(ins.getDefaultOperandRepresentation(1)):
        rd = frozenset()                    # XOR EAX, EAX: a write
    if mn in ("PUSH", "POP"):
        rd = frozenset() if mn == "PUSH" else rd     # PUSH EAX at the entry saves the caller's value
    if mn == "MOV" and ins.getNumOperands() == 2:
        # MOV DL, x writes part of the register; the result object is the sub-register: still a write
        pass
    return rd, wr


def _cfg(listing: Any, f: Any, Register: Any, callee_regs: Any) -> dict[int, Node] | None:
    """The nodes of ``live_regs`` for function ``f`` (None when it is too big to examine).
    ``callee_regs(function)`` gives the register arguments of a called function."""
    body = f.getBody()
    if int(body.getNumAddresses()) > MAX_BODY:
        return None
    fm = f.getProgram().getFunctionManager()
    nodes: dict[int, Node] = {}
    for ins in listing.getInstructions(body, True):
        ft = ins.getFlowType()
        rd, wr = _step(ins, Register)
        succ = []
        if ft.hasFallthrough():
            nxt = ins.getFallThrough()
            if nxt is not None:
                succ.append(int(nxt.getOffset()))
        targets = [t for t in (ins.getFlows() or ())]
        if ft.isCall() or ft.isJump():
            callee = None
            if len(targets) == 1 and not ft.isComputed():
                callee = fm.getFunctionAt(targets[0])
                if callee is not None and (callee.isExternal() or callee.isThunk()):
                    callee = None
            inside = callee is not None and callee.getEntryPoint() == f.getEntryPoint()
            if callee is not None and not inside:
                k = callee_regs(callee)
                rd = rd | frozenset(REGS[:k])
            if ft.isCall():
                wr = wr | frozenset(REGS)
            elif ft.isJump():
                for t in targets:
                    if body.contains(t):
                        succ.append(int(t.getOffset()))
        succ_t = tuple(succ)
        nodes[int(ins.getAddress().getOffset())] = (rd, wr, succ_t)
    return nodes


def _site_steps(call: Any, Register: Any) -> list[tuple[frozenset[str], frozenset[str]]]:
    """(read, written) of the straight-line instructions before ``call``, nearest first."""
    out = []
    ins = call.getPrevious()
    while ins is not None and len(out) < SITE_WINDOW:
        ft = ins.getFlowType()
        if ft.isCall() or ft.isJump() or ft.isTerminal():
            break
        out.append(_step(ins, Register))
        ins = ins.getPrevious()
    return out


def _ret_slots(listing: Any, body: Any) -> int | None:
    """Words that the function pops (``RET n``); None when it has no RET or its RETs differ."""
    sizes: set[int] = set()
    for ins in listing.getInstructions(body, True):
        if str(ins.getMnemonicString()).upper() in ("RET", "RETN"):
            n = 0
            if ins.getNumOperands():
                try:
                    n = int(str(ins.getDefaultOperandRepresentation(0)), 0)
                except ValueError:
                    return None
            sizes.add(n)
    return sizes.pop() // 4 if len(sizes) == 1 else None


def _reg_position(name: str) -> int:
    n = name.upper()
    return REGS.index(n) + 1 if n in REGS else 0


def _base_name(reg: Any) -> str:
    return str(reg.getBaseRegister().getName()).upper()


def _reg_params(params: list[Any]) -> dict[str, Any]:
    """The register parameters by base register (``DL`` is EDX)."""
    return {_base_name(p.getRegister()): p for p in params if p.isRegisterVariable() and p.getRegister() is not None}


def _pushes_before_write(listing: Any, entry: Any, Register: Any) -> bool:
    """True when the first instructions push EAX, EDX or ECX before writing it: a saved argument, or a slot
    reserved with ``PUSH ECX``; only the decompiler's data flow tells which."""
    written: set[str] = set()
    ins = listing.getInstructionAt(entry)
    for _ in range(8):
        if ins is None or ins.getFlowType().isCall() or ins.getFlowType().isTerminal():
            return False
        if str(ins.getMnemonicString()).upper() == "PUSH":
            if _folded(ins.getInputObjects(), Register) - written:
                return True
        written |= _step(ins, Register)[1]
        ins = ins.getNext()
    return False


def _narrow_bits(listing: Any, f: Any, name: str, Register: Any, callee_bits: Any) -> int:
    """Width in bits that the instructions of ``f`` read of register ``name`` when every read is narrow
    (``MOV [mem], DL``), else 32; a call or tail jump to a function that takes the register counts with the
    width that function reads (``callee_bits(function, name)``). No read at all: 32."""
    widest = 0
    fm = f.getProgram().getFunctionManager()
    for ins in listing.getInstructions(f.getBody(), True):
        for o in ins.getInputObjects():
            if isinstance(o, Register) and _base_name(o) == name:
                widest = max(widest, int(o.getBitLength()))
        ft = ins.getFlowType()
        if (ft.isCall() or ft.isJump()) and not ft.isComputed():
            flows = ins.getFlows() or ()
            c = fm.getFunctionAt(flows[0]) if len(flows) == 1 else None
            if c is not None and not c.isExternal() and not c.isThunk() and c.getEntryPoint() != f.getEntryPoint():
                widest = max(widest, callee_bits(c, name))
    return widest if 0 < widest < 32 else 32


def _site_bits(listing: Any, refman: Any, entry: Any, name: str, Register: Any) -> int:
    """Width in bits that every direct caller loads into register ``name`` when all of them load part of it
    (``MOV DL, 1``), else 32. A caller with no load of the register in reach counts as full width."""
    widest = 0
    n = 0
    for r in list(refman.getReferencesTo(entry))[:MAX_SITES]:
        if not r.getReferenceType().isCall():
            continue
        ins = listing.getInstructionAt(r.getFromAddress())
        bits = 32
        k = 0
        cur = ins.getPrevious() if ins is not None else None
        while cur is not None and k < SITE_WINDOW:
            ft = cur.getFlowType()
            if ft.isCall() or ft.isJump() or ft.isTerminal():
                break
            hit = [o for o in cur.getResultObjects() if isinstance(o, Register) and _base_name(o) == name]
            if hit:
                bits = int(hit[0].getBitLength())
                break
            cur = cur.getPrevious()
            k += 1
        if bits >= 32:
            return 32
        widest = max(widest, bits)
        n += 1
    return widest if n else 32


def _decompiled_regs(di: Any, f: Any) -> int:
    """Highest register position among the parameters that the decompiler infers for ``f`` (0 when it fails)."""
    try:
        res = di.decompileFunction(f, 20, None)
        hf = res.getHighFunction() if res.decompileCompleted() else None
        if hf is None:
            return 0
        proto = hf.getFunctionPrototype()
        best = 0
        for i in range(int(proto.getNumParams())):
            reg = proto.getParam(i).getStorage().getRegister()
            if reg is not None:
                best = max(best, _reg_position(_base_name(reg)))
        return best
    except Exception:  # noqa: BLE001
        return 0


def apply_register_prototypes(program: Any, is_stub: Any, monitor: Any = None) -> dict[str, int]:
    """Give the 32-bit Pascal functions that use the register convention their full prototype. Idempotent;
    must run inside a transaction. ``is_stub(function)`` tells the airlock stubs, which are left alone.
    Left as they are: functions with a user-defined signature, functions that pop nothing (``RET`` without a
    count) while Ghidra sees stack arguments (``cdecl``), Ghidra's ``stdcall`` / ``cdecl`` functions that read
    no register argument, and functions that read no register argument while no caller loads one."""
    from ghidra.program.model.data import Undefined1DataType, Undefined2DataType, Undefined4DataType  # type: ignore
    from ghidra.program.model.lang import Register  # type: ignore
    from ghidra.program.model.listing import Function, ParameterImpl, VariableStorage  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from java.util import ArrayList  # type: ignore

    out = {"proto": 0, "reordered": 0, "regs_added": 0, "decompiled": 0}
    listing = program.getListing()
    fm = program.getFunctionManager()
    refman = program.getReferenceManager()
    lang = program.getLanguage()
    stack = program.getAddressFactory().getStackSpace()
    word = Undefined4DataType.dataType
    known = {str(c.getName()) for c in program.getCompilerSpec().getCallingConventions()}
    default_conv = next((c for c in ("__register", "__fastcall") if c in known), None)
    memo: dict[int, int] = {}
    di = None
    bits_memo: dict[tuple[int, str], int] = {}

    def reg_bits(g: Any, name: str, depth: int = 0) -> int:
        """Bits that ``g`` reads of register ``name`` (0 when it takes none, 32 when unknown)."""
        key = (int(g.getEntryPoint().getOffset()), name)
        if key in bits_memo:
            return bits_memo[key]
        if depth > MAX_DEPTH or reg_args(g, 0) < _reg_position(name):
            return 0
        bits_memo[key] = 0
        old = _reg_params(list(g.getParameters())).get(name)
        if old is not None:
            bits_memo[key] = int(old.getLength()) * 8
        else:
            bits_memo[key] = min(_narrow_bits(listing, g, name, Register, lambda c, n: reg_bits(c, n, depth + 1)),
                                 _site_bits(listing, refman, g.getEntryPoint(), name, Register))
        return bits_memo[key]

    def reg_args(g: Any, depth: int) -> int:
        """Register arguments that the instructions of ``g`` read (a callee's count flows through)."""
        key = int(g.getEntryPoint().getOffset())
        if key in memo:
            return memo[key]
        if depth > MAX_DEPTH or is_stub(g):
            return 0
        memo[key] = 0               # a recursion reads what the first visit finds
        nodes = _cfg(listing, g, Register, lambda c: reg_args(c, depth + 1))
        memo[key] = live_regs(nodes, key) if nodes else 0
        if str(g.getCallingConventionName() or "") == "__register":     # what Ghidra stored earlier
            memo[key] = max(memo[key], max((_reg_position(n) for n in _reg_params(list(g.getParameters()))), default=0))
        return memo[key]

    for f in fm.getFunctions(True):
        if monitor is not None and monitor.isCancelled():
            break
        if f.isExternal() or f.isThunk() or is_stub(f) or f.getSignatureSource() == SourceType.USER_DEFINED:
            continue
        conv = str(f.getCallingConventionName() or "")
        entry = f.getEntryPoint()
        slots = _ret_slots(listing, f.getBody())
        if slots is None or slots > MAX_SLOTS:
            continue
        have = list(f.getParameters())
        if slots == 0 and any(p.isStackVariable() for p in have):
            continue            # the caller pops: cdecl
        regs = reg_args(f, 0)
        if conv == "__register":
            regs = max(regs, max((_reg_position(n) for n in _reg_params(have)), default=0))
        if regs < 3 and "__register" in known and conv in ("unknown", "default", "", "__register") \
                and not f.hasCustomVariableStorage() and _pushes_before_write(listing, entry, Register):
            if di is None:
                from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
                di = DecompInterface()
                di.setOptions(DecompileOptions())
                di.openProgram(program)
            regs = max(regs, _decompiled_regs(di, f))
            out["decompiled"] += 1
        if regs == 0 and conv not in ("__stdcall", "__cdecl"):
            sites = []
            for r in list(refman.getReferencesTo(entry))[:MAX_SITES]:
                c = listing.getInstructionAt(r.getFromAddress()) if r.getReferenceType().isCall() else None
                if c is not None:
                    sites.append(_site_steps(c, Register))
            regs = site_reg_count(sites)
        if regs == 0:
            continue
        if slots > 0:
            regs = 3            # stack arguments come after the three registers (some are not read)
        existing = [(int(p.getStackOffset()), int(p.getLength())) for p in have if p.isStackVariable()]
        reg_names, stack_args = wanted_layout(regs, slots, existing)
        by_off = {int(p.getStackOffset()): p for p in have if p.isStackVariable()}
        by_reg = _reg_params(have)
        cur = [(_base_name(p.getRegister()) if p.isRegisterVariable() else None,
                int(p.getStackOffset()) if p.isStackVariable() else None) for p in have]
        if cur == [(r, None) for r in reg_names] + [(None, o) for o, _s in stack_args] \
                and f.hasCustomVariableStorage():
            continue            # done before
        params = ArrayList()
        for rn in reg_names:
            old = by_reg.get(rn)
            if old is not None:             # keeps a byte or word register (``DL``) and the type
                typ, nm, store = old.getDataType(), old.getName() if old.getSource() != SourceType.DEFAULT else None, \
                    old.getVariableStorage()
            else:
                bits = reg_bits(f, rn)
                reg = lang.getRegister({"EAX": "AL", "EDX": "DL", "ECX": "CL"}[rn] if bits == 8 else
                                       {"EAX": "AX", "EDX": "DX", "ECX": "CX"}[rn] if bits == 16 else rn)
                typ = Undefined1DataType.dataType if bits == 8 else Undefined2DataType.dataType if bits == 16 else word
                nm, store = None, VariableStorage(program, [reg])
            params.add(ParameterImpl(nm, typ, store, program))
        for off, size in stack_args:
            old = by_off.get(off)
            if old is not None and int(old.getLength()) == size:
                typ, nm = old.getDataType(), (old.getName() if old.getSource() != SourceType.DEFAULT else None)
            else:
                typ, nm = word, None
            params.add(ParameterImpl(nm, typ, VariableStorage(program, stack.getAddress(off), size), program))
        try:
            if conv in ("unknown", "default", "") and default_conv:
                f.setCallingConvention(default_conv)      # no "unknown calling convention" warning in the C
            f.replaceParameters(params, Function.FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.ANALYSIS)
        except Exception:  # noqa: BLE001  one odd function must not stop the pass
            continue
        out["proto"] += 1
        out["reordered"] += len(stack_args) >= 2
        out["regs_added"] += len(reg_names) > sum(1 for p in have if p.isRegisterVariable())
    return out
