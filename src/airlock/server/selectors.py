"""Target resolution (DESIGN.md section 7.3). Server side; no Ghidra imports."""

from __future__ import annotations

import re
from dataclasses import dataclass

from airlock.index.store import Function, Store

_SPACE_ADDR = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(?:0[xX])?([0-9a-fA-F]+)$")
_BARE_HEX = re.compile(r"^[0-9a-fA-F]+$")
MAX_CANDIDATES = 20


@dataclass(frozen=True)
class Resolved:
    """Either ``function`` is set (with an optional ``note``) or ``error`` is
    a ready-to-print one-line error."""

    function: Function | None = None
    note: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.function is not None


def fmt_addr(value: int, pointer_size: int | None = 4, space: str = "ram") -> str:
    """``0x`` + lowercase hex zero-padded to pointer size; non-ram spaces get a prefix."""
    width = (pointer_size or 4) * 2
    s = f"0x{value:0{width}x}"
    return s if space == "ram" else f"{space}:{s}"


def parse_address(target: str) -> tuple[str, int] | None:
    """(space, offset) for ``0x...`` or ``SPACE:0x...``; None if not an
    explicit address. Rule 1 of 7.3."""
    t = target.strip()
    if t[:2].lower() == "0x":
        try:
            return "ram", int(t[2:], 16)
        except ValueError:
            return None
    m = _SPACE_ADDR.match(t)
    if m and (t.split(":", 1)[1][:2].lower() == "0x"):
        space = "EXTERNAL" if m.group(1).lower() == "external" else m.group(1)
        if m.group(1).lower() == "ram":
            space = "ram"
        return space, int(m.group(2), 16)
    return None


def _error(code: str, what: str, nxt: str) -> Resolved:
    return Resolved(error=f"error {code}: {what}. {nxt}.")


def resolve_function(store: Store, binary_id: int, target: str) -> Resolved:
    """Resolve ``target`` to a function of the binary.

    Order: explicit address, exact name (incl. namespace), bare hex address.
    Names matching several functions give an error listing every candidate.
    An address inside a function resolves to it, with a note.
    """
    target = target.strip()
    if not target:
        return _error("bad_target", "empty target", "Pass a function name or an address like 0x00401000")
    binary = store.get_binary_by_id(binary_id)
    psize = binary.pointer_size if binary else 4

    addr = parse_address(target)
    if addr is not None:
        return _by_address(store, binary_id, addr[0], addr[1], psize, target)

    fns = store.functions_by_name(binary_id, target)
    if len(fns) == 1:
        return Resolved(function=fns[0])
    if len(fns) > 1:
        shown = fns[:MAX_CANDIDATES]
        cands = ", ".join(fmt_addr(f.entry, psize, f.space) for f in shown)
        more = f" (+{len(fns) - len(shown)} more)" if len(fns) > len(shown) else ""
        return _error(
            "ambiguous",
            f"'{target}' matches {len(fns)} functions: {cands}{more}",
            "Retry with one of the addresses",
        )

    if _BARE_HEX.match(target):
        return _by_address(store, binary_id, "ram", int(target, 16), psize, target)

    return _error("not_found", f"no function named '{target}'", "Use search to find the name or pass an address")


def _by_address(
    store: Store, binary_id: int, space: str, value: int, psize: int | None, raw: str
) -> Resolved:
    fn = store.function_at(binary_id, value, space)
    if fn is not None:
        return Resolved(function=fn)
    fn = store.function_containing(binary_id, value, space)
    if fn is not None:
        a = fmt_addr(value, psize, space)
        e = fmt_addr(fn.entry, psize, space)
        return Resolved(function=fn, note=f"resolved from interior address {a} to {fn.qualified_name} at {e}")
    return _error(
        "not_found",
        f"no function at or containing {fmt_addr(value, psize, space)}",
        "Check the address or use search to find a function",
    )
