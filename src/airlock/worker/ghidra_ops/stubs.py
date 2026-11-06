"""The stub functions of the Delphi string pass (delphistr) and the block they live in.

They are an airlock artefact, not program content: the collector, the disassembler and the byte tools
skip them, and a decompiled call to a stub is attributed to the routine it stands for. Pure helpers, no
Ghidra imports, so tests can use fakes.
"""

from __future__ import annotations

from typing import Any

STUB_BLOCK = "airlock_stubs"
STUB_TAG = "airlock:concat "      # function comment of a stub: "<tag><callee entry hex> <piece count>"


def stub_block(program: Any) -> Any:
    return program.getMemory().getBlock(STUB_BLOCK)


def stub_range(program: Any) -> tuple[int, int] | None:
    """(first, last) offset of the stub block, None when the program has none."""
    blk = stub_block(program)
    if blk is None:
        return None
    return int(blk.getStart().getOffset()), int(blk.getEnd().getOffset())


def in_range(rng: tuple[int, int] | None, off: int) -> bool:
    return rng is not None and rng[0] <= off <= rng[1]


def in_stubs(program: Any, addr: Any) -> bool:
    """True when ``addr`` lies in the stub block."""
    if addr is None:
        return False
    blk = program.getMemory().getBlock(addr)
    return blk is not None and str(blk.getName()) == STUB_BLOCK


def parse_tag(comment: Any) -> tuple[int, int] | None:
    """(callee entry, piece count) from a stub's function comment."""
    text = str(comment or "")
    if not text.startswith(STUB_TAG):
        return None
    try:
        e, n = text[len(STUB_TAG):].split()
        return int(e, 16), int(n)
    except ValueError:
        return None


def stub_functions(program: Any) -> list[tuple[Any, int, int]]:
    """(function, callee entry, piece count) of every stub."""
    blk = stub_block(program)
    if blk is None:
        return []
    out = []
    end = blk.getEnd()
    for fn in program.getFunctionManager().getFunctions(blk.getStart(), True):
        if fn.getEntryPoint().compareTo(end) > 0:
            break
        tag = parse_tag(fn.getComment())
        if tag is not None:
            out.append((fn, tag[0], tag[1]))
    return out


def real_target(program: Any, off: int) -> tuple[int, int] | None:
    """(routine entry, piece count) of the stub at offset ``off``; None when ``off`` is no stub."""
    rng = stub_range(program)
    if not in_range(rng, off):
        return None
    fn = program.getFunctionManager().getFunctionAt(
        program.getAddressFactory().getDefaultAddressSpace().getAddress(off))
    return parse_tag(fn.getComment()) if fn is not None else None


def is_vcall_stub(program: Any, off: int) -> bool:
    """True when ``off`` is the entry of a stub of an indirect call (tag ``airlock:concat vcall <key>``): it
    stands for no routine, so a decompiled call to it has no target address."""
    rng = stub_range(program)
    if not in_range(rng, off):
        return False
    fn = program.getFunctionManager().getFunctionAt(
        program.getAddressFactory().getDefaultAddressSpace().getAddress(off))
    return fn is not None and str(fn.getComment() or "").startswith(STUB_TAG + "vcall ")


def real_callee(program: Any, off: int) -> int:
    """The routine a stub at offset ``off`` stands for; ``off`` itself when it is no stub."""
    tag = real_target(program, off)
    return tag[0] if tag is not None else off


def stub_name(callee_name: str, n: int) -> str:
    return f"{callee_name}_{n}"


def rename_for(program: Any, callee: Any) -> int:
    """Rename the stubs of ``callee`` to follow its current name; returns how many changed. Needs a
    transaction."""
    from ghidra.program.model.symbol import SourceType  # type: ignore
    entry = int(callee.getEntryPoint().getOffset())
    changed = 0
    for fn, e, n in stub_functions(program):
        want = stub_name(str(callee.getName()), n)
        if e != entry or str(fn.getName()) == want:
            continue
        try:
            fn.setName(want, SourceType.USER_DEFINED)
            changed += 1
        except Exception:  # noqa: BLE001  a duplicate name: keep the old one
            pass
    return changed


def rename_all(program: Any) -> int:
    """Bring every stub name in line with its routine; returns how many changed. Needs a transaction."""
    fm = program.getFunctionManager()
    sp = program.getAddressFactory().getDefaultAddressSpace()
    changed = 0
    done: set[int] = set()
    for _fn, e, _n in stub_functions(program):
        if e in done:
            continue
        done.add(e)
        callee = fm.getFunctionAt(sp.getAddress(e))
        if callee is not None:
            changed += rename_for(program, callee)
    return changed


def program_function_count(program: Any) -> int:
    """Function count without the stubs."""
    n = int(program.getFunctionManager().getFunctionCount())
    if stub_block(program) is None:
        return n
    return n - len(stub_functions(program))
