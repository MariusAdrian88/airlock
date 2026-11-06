"""Helpers shared by the tool modules: binary lookup, budgets, line formatting."""

from __future__ import annotations

from dataclasses import dataclass

from airlock.index.store import Binary, Function, Store
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.selectors import MAX_CANDIDATES, fmt_addr, resolve_function, split_binary_suffix, split_binary_target


@dataclass(frozen=True)
class Bound:
    project: str
    store: Store
    binary: Binary

    @property
    def psize(self) -> int:
        return self.binary.pointer_size or 4

    def addr(self, value: int, space: str = "ram") -> str:
        return fmt_addr(value, self.psize, space)


def bind_binary(ctx: ServerContext, binary: str = "", *, require_ready: bool = True,
                project: str | None = None) -> Bound | str:
    """Resolve the project and binary; returns Bound or a one-line error string.

    ``binary`` may be omitted when the project has exactly one binary."""
    ix = ctx.indexer
    try:
        proj = ix.resolve_project(project)
    except IndexerError as e:
        return e.message
    st = ix.store(proj)
    if binary:
        found = st.find_binaries(binary)
        if not found:
            names = ", ".join(b.name for b in st.list_binaries()) or "none"
            return f"error not_found: no binary '{binary}' in project '{proj}' (have: {names})."
        if len(found) > 1:
            return (f"error ambiguous_binary: '{binary}' matches {len(found)} binaries: "
                    f"{', '.join(f'{x.name} ({x.sha256[:12]})' for x in found[:MAX_CANDIDATES])}.")
        b = found[0]
    else:
        every = st.list_binaries()
        if not every:
            return f"error no_binary: project '{proj}' has no binaries."
        if len(every) > 1:
            return (f"error ambiguous_binary: project '{proj}' has {len(every)} binaries: "
                    f"{', '.join(x.name for x in every)}.")
        b = every[0]
    if require_ready:
        err = ix.not_ready_error(proj, st, b)
        if err:
            return err
    return Bound(proj, st, b)


def bound_of(bd: Bound, binary_id: int) -> Bound:
    """Bound for another binary of the same project store."""
    if bd.binary.id == binary_id:
        return bd
    b = bd.store.get_binary_by_id(binary_id)
    assert b is not None
    return Bound(bd.project, bd.store, b)


def bind_many(ctx: ServerContext, binary: str = "") -> tuple[list[Bound], int] | str:
    """Binaries a search-like tool covers: ``binary`` if given, else every ready binary.

    Returns ``(bounds, skipped)`` (skipped = binaries not ready) or an error line. A project
    with one binary behaves as in ``bind_binary``."""
    if binary:
        bd = bind_binary(ctx, binary)
        return bd if isinstance(bd, str) else ([bd], 0)
    ix = ctx.indexer
    try:
        proj = ix.resolve_project(None)
    except IndexerError as e:
        return e.message
    st = ix.store(proj)
    every = st.list_binaries()
    if len(every) <= 1:
        bd = bind_binary(ctx, "")
        return bd if isinstance(bd, str) else ([bd], 0)
    ready = [Bound(proj, st, b) for b in every if ix.not_ready_error(proj, st, b) is None]
    if not ready:
        return ix.not_ready_error(proj, st, every[0]) or "error not_analysed: no binary is ready."
    return ready, len(every) - len(ready)


def bind_target(ctx: ServerContext, binary: str, target: str) -> tuple[Bound, str, str | None] | str:
    """Resolve ``binary`` and ``target`` (which may be ``binary!target``) to
    ``(Bound, bare_target, note)`` or an error line. DESIGN 7.3 rule 6.

    With no binary given in a multi-binary project the bare target is looked up in every ready
    binary: exactly one hit wins (``note`` names the binary), several give ``error ambiguous``."""
    ix = ctx.indexer
    try:
        proj = ix.resolve_project(None)
    except IndexerError as e:
        return e.message
    st = ix.store(proj)
    pre, bare = split_binary_target(st, target)
    if pre:
        if binary and not any(b.name.lower() == pre.lower() for b in st.find_binaries(binary)):
            return f"error bad_args: target names binary '{pre}' but binary='{binary}'."
        bd = bind_binary(ctx, pre)
        return bd if isinstance(bd, str) else (bd, bare, None)
    if binary or len(st.list_binaries()) <= 1:
        bd = bind_binary(ctx, binary)
        return bd if isinstance(bd, str) else (bd, target, None)
    many = bind_many(ctx, "")
    if isinstance(many, str):
        return many
    bounds, skipped = many
    cands: list[tuple[Bound, Function]] = []
    for bd in bounds:
        r = resolve_function(bd.store, bd.binary.id, bare)
        if r.function is not None:
            cands.append((bd, r.function))
        elif r.error and r.error.startswith("error ambiguous"):
            cands += [(bd, f) for f in bd.store.functions_by_name(bd.binary.id, bare)]
    if len(cands) == 1:
        bd = cands[0][0]
        return bd, bare, f"binary {bd.binary.name}"
    if not cands:
        extra = f" ({skipped} not ready)" if skipped else ""
        return f"error not_found: no function '{bare}' in {len(bounds)} ready binaries{extra}."
    shown = cands[:MAX_CANDIDATES]
    lst = ", ".join(f"{bd.binary.name}!{f.qualified_name} {bd.addr(f.entry, f.space)}"
                    for bd, f in shown)
    more = f" (+{len(cands) - len(shown)} more)" if len(cands) > len(shown) else ""
    return f"error ambiguous: '{bare}' matches {len(cands)} functions: {lst}{more}."


@dataclass(frozen=True)
class Scope:
    """Where a target is looked up: the binaries, the target text without a binary prefix, and
    whether the binary was named (prefix, ``binary=``, or a single-binary project)."""

    project: str
    store: Store
    bounds: tuple[Bound, ...]
    bare: str
    explicit: bool
    skipped: int = 0


def bind_scope(ctx: ServerContext, binary: str, target: str) -> Scope | str:
    """Like ``bind_target`` but without resolving the name: one binary when it is named (DESIGN
    7.3 rule 6) or the only one, else every ready binary. Returns a Scope or an error line."""
    ix = ctx.indexer
    try:
        proj = ix.resolve_project(None)
    except IndexerError as e:
        return e.message
    st = ix.store(proj)
    t = target.strip()
    if len(t) > 3 and t[0] == "<" and ">!" in t:          # <main.exe>!name
        t = t[1:].replace(">!", "!", 1)
    pre, bare = split_binary_target(st, t)
    if not pre:
        pre, bare = split_binary_suffix(st, t)
    if pre:
        if binary and not any(b.name.lower() == pre.lower() for b in st.find_binaries(binary)):
            return f"error bad_args: target names binary '{pre}' but binary='{binary}'."
        bd = bind_binary(ctx, pre)
        return bd if isinstance(bd, str) else Scope(proj, st, (bd,), bare, True)
    if binary or len(st.list_binaries()) <= 1:
        bd = bind_binary(ctx, binary)
        return bd if isinstance(bd, str) else Scope(proj, st, (bd,), t, True)
    many = bind_many(ctx, "")
    if isinstance(many, str):
        return many
    bounds, skipped = many
    return Scope(proj, st, tuple(bounds), t, False, skipped)


FALLBACK_BUDGETS = {"token_budget": 2000, "function_budget": 10000, "max_budget": 32000}


def budget_for(ctx: ServerContext, budget: int = 0, key: str = "token_budget") -> int:
    """Per-call budget: `budget` if given (capped), else the config default `key`.

    The cap is never below the tool's own default, so an override can always
    ask for at least what the tool returns without one.
    """
    d = ctx.config.defaults
    default = int(d.get(key) or FALLBACK_BUDGETS[key])
    cap = max(int(d.get("max_budget") or FALLBACK_BUDGETS["max_budget"]), default)
    return max(100, min(int(budget), cap)) if budget and budget > 0 else default


def preview(value: str, n: int = 80) -> str:
    """One-line quoted preview of a string with control characters escaped."""
    s = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if len(s) > n:
        s = s[: n - 1] + "…"
    return f'"{s}"'


def fn_label(fn: Function) -> str:
    return fn.qualified_name


def fn_desc(b: Bound, fn: Function) -> str:
    """``name (0xaddr)``."""
    return f"{fn.qualified_name} ({b.addr(fn.entry, fn.space)})"
