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

from typing import Any

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
        if f.isExternal() or f.isThunk() or int(f.getBody().getNumAddresses()) > MAX_HELPER_SIZE:
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
