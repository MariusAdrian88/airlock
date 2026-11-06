"""Round 10 group B: on-demand function creation never damages the project (R2, R3), direct call targets are
created by the fix pass (R4). Fake worker and fake Ghidra objects."""

from __future__ import annotations

import sys
import types

from airlock.server import fnfix, targets as tg
from airlock.server.tools import core
from airlock.worker.ghidra_ops import funcs
from test_r9d import _setup, _W
from test_xbin_tools import _fn


def test_string_in_code_is_no_function(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch)
    st.insert_strings(bid, [(addr, "ascii", "[Settings]")])
    out = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION,))
    assert isinstance(out, str)
    assert out.startswith(f'error not_found: no function at 0x{addr:08x}; it is the string "[Settings]"')
    assert "\n" not in out and ctx.worker.calls == []        # nothing was sent to Ghidra


class _DataW(_W):
    def request(self, op, args, timeout=0):
        if op == "create_functions":
            self.calls.append(op)
            return {"created": 0, "data": {hex(self.addr): "pointer 0x401234"}}
        return super().request(op, args, timeout)


def test_worker_data_reply_is_one_fact_line(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch)
    ctx.worker = ctx.indexer.worker = _DataW(st, bid, addr)
    out = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION,))
    assert isinstance(out, str) and "it is data (pointer 0x401234)" in out and "with no references" in out


class _InnerW(_W):
    def __init__(self, st, bid, outer, inner):
        super().__init__(st, bid, outer)
        self.inner = inner

    def request(self, op, args, timeout=0):
        if op == "create_functions":
            self.calls.append(op)
            self.sent = args
            return {"created": 1, "conventions": {}, "resolved": {hex(self.inner): hex(self.addr)}}
        if op == "extract_at":
            self.read = args["addresses"]
        return super().request(op, args, timeout)


def test_interior_address_resolves_to_the_routine(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch)
    inner = addr + 0x70
    ctx.worker = ctx.indexer.worker = w = _InnerW(st, bid, addr, inner)
    t = tg.resolve_target(ctx, "", f"0x{inner:08x}", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == addr
    assert w.read == [addr] and "is inside the code that starts at" in t.note
    assert "known_code" not in w.sent                      # an on-demand call is never trusted


def test_xrefs_resolution_does_not_create(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch)
    r = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION, tg.ADDRESS), create=False)
    assert ctx.worker.calls == [] and not isinstance(r, tg.FunctionTarget)
    out = core.xrefs(ctx, f"0x{addr:08x}")
    assert "created one" not in out and ctx.worker.calls == []


def test_fnfix_adds_call_targets_outside_functions(tmp_path):
    from test_fnfix import _setup as fsetup
    ctx, st, bid = fsetup(tmp_path)
    assert fnfix.FIX_VERSION >= 6
    base = fnfix.candidates(st, bid)
    st.insert_functions(bid, [_fn(0x402000, "Big", 0x100)])
    st.insert_edges(bid, [(0x401004, 0x405000, "call"),      # a gap: candidate
                          (0x401008, 0x402040, "call"),      # inside Big: no
                          (0x40100c, 0x405100, "jump")])     # a jump: no
    st.link_edges(bid)
    got = fnfix.candidates(st, bid)
    assert 0x405000 in got and 0x402040 not in got and 0x405100 not in got
    assert set(base) <= set(got)


# -- worker op with fake Ghidra objects --------------------------------------------------------------------

class _Addr:
    def __init__(self, v):
        self.v = v

    def equals(self, o):
        return self.v == o.v

    def getOffset(self):
        return self.v


class _Type:
    def __init__(self, call=False, jump=False):
        self.c, self.j = call, jump

    def isCall(self):
        return self.c

    def isJump(self):
        return self.j


class _Ref:
    def __init__(self, t):
        self.t = t

    def getReferenceType(self):
        return self.t


class _Data:
    def __init__(self, a):
        self.a = a

    def isDefined(self):
        return True

    def getMinAddress(self):
        return self.a

    def getMaxAddress(self):
        return self.a

    def getDataType(self):
        return types.SimpleNamespace(getName=lambda: "string")

    def getDefaultValueRepresentation(self):
        return '"[Settings]"'


class _Prog:
    def __init__(self, refs, data_at):
        self.cleared, self.refs, self.data_at = [], refs, data_at
        blk = types.SimpleNamespace(isExecute=lambda: True, isInitialized=lambda: True)
        self.mem = types.SimpleNamespace(getBlock=lambda a: blk)
        self.fm = types.SimpleNamespace(getFunctionContaining=lambda a: None)
        prog = self
        self.lst = types.SimpleNamespace(
            getInstructionContaining=lambda a: None, getInstructionAt=lambda a: None,
            getDataContaining=lambda a: prog.data_at,
            clearCodeUnits=lambda lo, hi, ctx: prog.cleared.append((lo.v, hi.v)))
        self.rm = types.SimpleNamespace(getReferencesTo=lambda a: prog.refs)

    def getFunctionManager(self):
        return self.fm

    def getListing(self):
        return self.lst

    def getMemory(self):
        return self.mem

    def getReferenceManager(self):
        return self.rm


def test_worker_keeps_defined_data_without_flow_reference():
    a = _Addr(0x4c1df8)
    prog = _Prog([_Ref(_Type())], _Data(a))             # a data reference only
    extra: dict = {}
    assert funcs._one(prog, a, None, False, extra) == "data"
    assert prog.cleared == [] and extra["data"][0x4c1df8].startswith("string")


def test_worker_trusted_or_called_data_is_cleared(monkeypatch):
    a = _Addr(0x4c1df8)
    monkeypatch.setattr(funcs, "_make", lambda p, ad, m: "created")
    prog = _Prog([_Ref(_Type(call=True))], _Data(a))    # a call points here: it is code
    assert funcs._one(prog, a, None, False, {}) == "created" and prog.cleared == [(0x4c1df8, 0x4c1df8)]
    prog = _Prog([], _Data(a))
    assert funcs._one(prog, a, None, True, {}) == "created"      # known code (static tables)


def test_failed_trial_is_undone(monkeypatch):
    seen: list = []
    rng = types.SimpleNamespace(getMinAddress=lambda: _Addr(0x10), getMaxAddress=lambda: _Addr(0x1f))

    class Dis:
        def __init__(self, *a):
            pass

        def applyTo(self, p, m):
            seen.append(1)
            return True

        def getDisassembledAddressSet(self):
            return [rng]

    class Create:
        def __init__(self, *a):
            pass

        def applyTo(self, p, m):
            return False

    for name, attr, cls in (("ghidra.app.cmd.disassemble", "DisassembleCommand", Dis),
                            ("ghidra.app.cmd.function", "CreateFunctionCmd", Create)):
        mod = types.ModuleType(name)
        setattr(mod, attr, cls)
        monkeypatch.setitem(sys.modules, name, mod)
    prog = _Prog([], None)
    removed: list = []
    prog.rm.removeAllReferencesFrom = lambda lo, hi: removed.append((lo.v, hi.v))
    prog.lst.getInstructionAt = lambda a: object() if seen else None    # the trial produced an instruction
    prog.fm.getFunctionAt = lambda a: None
    assert funcs._make(prog, _Addr(0x10), None) == "failed"
    assert prog.cleared == [(0x10, 0x1f)] and removed == [(0x10, 0x1f)]


def test_delphi_string_header_is_no_function(tmp_path, monkeypatch):
    ctx, st, bid, base, addr = _setup(tmp_path, monkeypatch)
    st.insert_strings(bid, [(addr + 4, "ascii", "Tile Studio")])        # the header sits before the characters
    out = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION,))
    assert isinstance(out, str) and "inside or just before the string" in out and ctx.worker.calls == []
    out = tg.resolve_target(ctx, "", f"0x{addr + 6:08x}", (tg.FUNCTION,))
    assert isinstance(out, str) and "inside or just before the string" in out
