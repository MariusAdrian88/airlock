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


def split_binary_target(store: Store, target: str) -> tuple[str, str]:
    """``(binary, bare_target)`` for ``binary!target``, else ``("", target)``.

    Splits on the first ``!`` only when the left part is the exact name (case-insensitive) of
    a binary of the project, so names that contain ``!`` stay intact. Rule 6 of 7.3."""
    t = target.strip()
    left, sep, right = t.partition("!")
    left, right = left.strip(), right.strip()
    if sep and left and right:
        for b in store.list_binaries():
            if b.name.lower() == left.lower():
                return b.name, right
    return "", t


def split_binary_suffix(store: Store, target: str) -> tuple[str, str]:
    """``(binary, bare_target)`` for ``name@binary``, else ``("", target)``. Splits on the last
    ``@`` only when the right part is the exact name of a binary (decorated names like
    ``_foo@8`` stay intact). Rule 9 of 7.3."""
    t = target.strip()
    left, sep, right = t.rpartition("@")
    left, right = left.strip(), right.strip()
    if sep and left and right:
        for b in store.list_binaries():
            if b.name.lower() == right.lower():
                return b.name, left
    return "", t


def _error(code: str, what: str, nxt: str = "") -> Resolved:
    return Resolved(error=f"error {code}: {what}." + (f" {nxt}." if nxt else ""))


MAX_CLOSE = 8   # close names listed in a not_found error


def close_functions(store: Store, binary_id: int, name: str, limit: int = MAX_CLOSE) -> tuple[list[Function], bool]:
    """Functions whose name is close to ``name``: (rows, exact_ignoring_case). First the names
    equal to it ignoring case (also ``ns::name``); else names that contain its last segment
    (after ``::``, ``.`` or ``!``), shortest first. Only the first kind is safe to resolve to."""
    t = name.strip()
    if not t:
        return [], False
    rows = store.db.execute(
        "SELECT entry, space FROM function WHERE binary_id=? AND (lower(name)=lower(?) OR "
        "(namespace IS NOT NULL AND namespace<>'' AND lower(namespace || '::' || name)=lower(?))) "
        "ORDER BY space, entry LIMIT ?", (binary_id, t, t, limit + 1)).fetchall()
    if rows:
        exact = True
    else:
        tail = re.split(r"::|[.!]", t)[-1]
        if len(tail) < 3:
            return [], False
        like = "%" + tail.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = store.db.execute(
            "SELECT entry, space FROM function WHERE binary_id=? AND name LIKE ? ESCAPE '\\' "
            "ORDER BY length(name), entry LIMIT ?", (binary_id, like, limit + 1)).fetchall()
        exact = False
    fns = [f for f in (store.function_at(binary_id, r[0], r[1]) for r in rows) if f is not None]
    local = [f for f in fns if not f.is_external]
    if exact and len(fns) > 1 and len(local) == 1:   # an import's EXTERNAL row and its thunk
        fns = local
    return fns, exact


def close_text(names: list[str], more: bool) -> str:
    """``close names: a 0x.., b 0x..`` for a not_found error, or empty."""
    if not names:
        return ""
    return "close names: " + ", ".join(names) + (" …" if more else "")


def resolve_function(store: Store, binary_id: int, target: str) -> Resolved:
    """Resolve ``target`` to a function of the binary.

    Order: explicit address, exact name (incl. namespace), bare hex address.
    Names matching several functions give an error listing every candidate.
    An address inside a function resolves to it, with a note.
    """
    target = target.strip()
    if not target:
        return _error("bad_target", "empty target")
    binary = store.get_binary_by_id(binary_id)
    psize = binary.pointer_size if binary else 4

    addr = parse_address(target)
    if addr is not None:
        return _by_address(store, binary_id, addr[0], addr[1], psize, target)

    fns = store.functions_by_name(binary_id, target)
    if len(fns) == 1:
        return Resolved(function=fns[0])
    if len(fns) > 1:
        # An imported function is an EXTERNAL row plus a ram thunk of the same
        # name; the thunk is the one with callers, so external rows lose the tie.
        local = [f for f in fns if not f.is_external]
        if len(local) == 1:
            return Resolved(function=local[0])
    if len(fns) > 1:
        shown = fns[:MAX_CANDIDATES]
        cands = ", ".join(fmt_addr(f.entry, psize, f.space) for f in shown)
        more = f" (+{len(fns) - len(shown)} more)" if len(fns) > len(shown) else ""
        return _error(
            "ambiguous",
            f"'{target}' matches {len(fns)} functions: {cands}{more}",
        )

    if _BARE_HEX.match(target):
        return _by_address(store, binary_id, "ram", int(target, 16), psize, target)

    close, exact = close_functions(store, binary_id, target)
    if exact and len(close) == 1:
        f = close[0]
        return Resolved(function=f, note=f"resolved '{target}' to {f.qualified_name} (case differs)")
    names = [f"{f.qualified_name} {fmt_addr(f.entry, psize, f.space)}" for f in close[:MAX_CLOSE]]
    return _error("not_found", f"no function named '{target}'", close_text(names, len(close) > MAX_CLOSE))


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
    )
