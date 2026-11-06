"""The airlock stubs (delphistr concat stubs) are no program content: synthetic fakes, no Ghidra."""

from __future__ import annotations

import sys
import types
from typing import Any

from airlock.worker.ghidra_ops import decompile, extract, stubs

LO, HI = 0x900000, 0x900FFF


class Space:
    def getName(self) -> str:
        return "ram"

    def getAddress(self, off: int) -> "Addr":
        return Addr(off)


class Addr:
    def __init__(self, off: int) -> None:
        self.off = off

    def getOffset(self) -> int:
        return self.off

    def getAddressSpace(self) -> Space:
        return Space()

    def compareTo(self, o: "Addr") -> int:
        return (self.off > o.off) - (self.off < o.off)

    def isMemoryAddress(self) -> bool:
        return True


class Block:
    def __init__(self, name: str, lo: int, hi: int) -> None:
        self.name, self.lo, self.hi = name, lo, hi

    def getName(self) -> str:
        return self.name

    def getStart(self) -> Addr:
        return Addr(self.lo)

    def getEnd(self) -> Addr:
        return Addr(self.hi)


class Sym:
    def getSource(self) -> Any:
        return types.SimpleNamespace(name=lambda: "USER_DEFINED")


class Ns:
    def isGlobal(self) -> bool:
        return True


class Fn:
    def __init__(self, entry: int, name: str, comment: str = "") -> None:
        self.entry, self.name, self.comment = entry, name, comment

    def getEntryPoint(self) -> Addr:
        return Addr(self.entry)

    def getName(self) -> str:
        return self.name

    def setName(self, name: str, _src: Any) -> None:
        self.name = name

    def getComment(self) -> str:
        return self.comment

    def getSymbol(self) -> Sym:
        return Sym()

    def getParentNamespace(self) -> Ns:
        return Ns()

    def getPrototypeString(self, *_a: Any) -> str:
        return "void f(void)"

    def getCallingConventionName(self) -> str:
        return "__stdcall"

    def getBody(self) -> Any:
        return types.SimpleNamespace(getNumAddresses=lambda: 1)

    def isThunk(self) -> bool:
        return False

    def isExternal(self) -> bool:
        return False


class Ref:
    def __init__(self, to: int, kind: str = "call") -> None:
        self.to, self.kind = to, kind

    def isMemoryReference(self) -> bool:
        return True

    def isExternalReference(self) -> bool:
        return False

    def getToAddress(self) -> Addr:
        return Addr(self.to)

    def getReferenceType(self) -> Any:
        return types.SimpleNamespace(isCall=lambda: True, isComputed=lambda: False, isIndirect=lambda: False)


class Program:
    def __init__(self, with_block: bool = True) -> None:
        self.real = Fn(0x401000, "RealConcat")
        self.stub3 = Fn(LO, "RealConcat_3", f"{stubs.STUB_TAG}401000 3")
        self.stub5 = Fn(LO + 16, "RealConcat_5", f"{stubs.STUB_TAG}401000 5")
        self.caller = Fn(0x402000, "caller")
        self.fns = [self.real, self.caller, self.stub3, self.stub5]
        self.blocks = [Block(".text", 0x401000, 0x4fffff)] + ([Block(stubs.STUB_BLOCK, LO, HI)] if with_block else [])
        # the caller's call instruction at 0x402010: the real call and the override to the stub
        self.refs = {0x402010: [Ref(0x401000), Ref(LO)], LO: [Ref(0x401000)]}

    def getMemory(self) -> Any:
        def block_at(a: Addr) -> Any:
            return next((b for b in self.blocks if b.lo <= a.off <= b.hi), None)

        def block_named(x: Any) -> Any:
            if isinstance(x, str):
                return next((b for b in self.blocks if b.name == x), None)
            return block_at(x)
        return types.SimpleNamespace(getBlock=block_named, getBlocks=lambda: self.blocks)

    def getAddressFactory(self) -> Any:
        return types.SimpleNamespace(getDefaultAddressSpace=Space)

    def getFunctionManager(self) -> Any:
        prog = self

        class FM:
            def getFunctionAt(self, a: Addr) -> Any:
                return next((f for f in prog.fns if f.entry == a.off), None)

            def getFunctions(self, arg: Any, _fwd: bool = True) -> Any:
                if isinstance(arg, bool):
                    return iter(prog.fns)
                return iter(sorted((f for f in prog.fns if f.entry >= arg.off), key=lambda f: f.entry))

            def getExternalFunctions(self) -> Any:
                return iter(())

            def getFunctionContaining(self, a: Addr) -> Any:
                return next((f for f in prog.fns if f.entry <= a.off < f.entry + 0x100), None)

            def getFunctionCount(self) -> int:
                return len(prog.fns)
        return FM()

    def getReferenceManager(self) -> Any:
        prog = self

        class RM:
            def getReferenceSourceIterator(self, _mem: Any, _fwd: bool) -> Any:
                class It:
                    def __init__(s) -> None:
                        s.keys = iter(sorted(prog.refs))
                        s.nxt = next(s.keys, None)

                    def hasNext(s) -> bool:
                        return s.nxt is not None

                    def next(s) -> Addr:
                        v, s.nxt = s.nxt, next(s.keys, None)
                        return Addr(v)
                return It()

            def getReferencesFrom(self, a: Addr) -> Any:
                return prog.refs.get(a.off, [])
        return RM()


def _fake_symbol_module(monkeypatch: Any) -> None:
    mod = types.ModuleType("ghidra.program.model.symbol")
    mod.SourceType = types.SimpleNamespace(USER_DEFINED="U")
    for name in ("ghidra", "ghidra.program", "ghidra.program.model"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", mod)


def test_range_and_membership():
    p = Program()
    assert stubs.stub_range(p) == (LO, HI)
    assert stubs.in_stubs(p, Addr(LO + 16)) and not stubs.in_stubs(p, Addr(0x401000))
    assert stubs.stub_range(Program(with_block=False)) is None
    assert not stubs.in_range(None, LO)


def test_tag_and_real_callee():
    assert stubs.parse_tag(f"{stubs.STUB_TAG}401000 3") == (0x401000, 3)
    assert stubs.parse_tag("something else") is None and stubs.parse_tag(None) is None
    p = Program()
    assert stubs.real_callee(p, LO + 16) == 0x401000
    assert stubs.real_callee(p, 0x402000) == 0x402000          # no stub: unchanged
    assert stubs.real_callee(p, LO + 0x80) == LO + 0x80        # in the block, no function


def test_function_count_without_stubs():
    assert stubs.program_function_count(Program()) == 2
    assert stubs.program_function_count(Program(with_block=False)) == 4


def test_extract_functions_skip_stubs():
    p = Program()
    names = [r[2] for r in extract._functions(p)]
    assert names == ["RealConcat", "caller"]


def test_extract_edges_skip_stubs():
    p = Program()
    rows = list(extract._edges(p))
    assert len(rows) == 1
    src, _fn, _sp, dst, _dfn, kind = rows[0]
    assert (src, dst, kind) == (0x402010, 0x401000, "call")     # the real call; the override and the stub's own edges are gone


def test_decompile_calls_point_at_the_real_routine():
    p = Program()
    rows = [["call", 0, 4, 0x402010, LO, "RealConcat_3"], ["call", 5, 9, 0x402020, 0x401000, "RealConcat"],
            ["call", 9, 12, 0x402030, None, "x"], ["str_ref", 0, 1, 0, LO, "s"]]
    decompile._unstub_calls(p, rows, "abcd efghijkl")
    assert [r[4] for r in rows] == [0x401000, 0x401000, None, LO]      # only call rows change


def test_decompile_text_names_the_real_routine():
    p = Program()
    text = "x = RealConcat_3(a, \"s\"); y = RealConcat_3(b); z = q(c);"
    s1 = text.index("RealConcat_3")
    s2 = text.index("RealConcat_3", s1 + 1)
    s3 = text.index("q(")
    s4 = text.index('"s"')
    rows = [["call", s1, s1 + 12, 0x402010, LO, "RealConcat_3"],
            ["str_ref", s4, s4 + 3, 0, 0, '"s"'],
            ["call", s2, s2 + 12, 0x402020, LO, "RealConcat_3"],
            ["call", s3, s3 + 1, 0x402030, 0x401000, "q"]]
    out = decompile._unstub_calls(p, rows, text)
    assert out == 'x = RealConcat(a, "s"); y = RealConcat(b); z = q(c);'
    for r in rows:
        assert out[r[1]:r[2]] == r[5]
    assert [r[4] for r in rows if r[0] == "call"] == [0x401000] * 3
    assert "_3" not in out and hex(LO) not in out


def test_rename_follows_the_routine(monkeypatch):
    _fake_symbol_module(monkeypatch)
    p = Program()
    p.real.name = "@System@@LStrCatN$qqrv"
    assert stubs.rename_for(p, p.real) == 2
    assert p.stub3.name == "@System@@LStrCatN$qqrv_3" and p.stub5.name == "@System@@LStrCatN$qqrv_5"
    assert stubs.rename_for(p, p.real) == 0
    p.real.name = "again"
    assert stubs.rename_all(p) == 2 and p.stub5.name == "again_5"


def test_create_function_refuses_the_stub_block():
    import pytest
    from airlock.worker.ghidra_ops import funcs
    from airlock.worker.protocol import WorkerError
    p = Program()
    funcs._refuse_stub(p, Addr(0x401000))
    with pytest.raises(WorkerError) as ex:
        funcs._refuse_stub(p, Addr(LO + 16))
    assert ex.value.code == "bad_args" and "not in the program's memory" in str(ex.value)
