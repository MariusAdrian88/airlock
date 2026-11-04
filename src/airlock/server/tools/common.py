"""Helpers shared by the tool modules: binary lookup, budgets, line formatting."""

from __future__ import annotations

from dataclasses import dataclass

from airlock.index.store import Binary, Function, Store
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.selectors import fmt_addr


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
            return (f"error not_found: no binary '{binary}' in project '{proj}' (have: {names}). "
                    "Call list_binaries.")
        if len(found) > 1:
            return (f"error ambiguous_binary: '{binary}' matches {len(found)} binaries. "
                    "Use a longer sha256 prefix.")
        b = found[0]
    else:
        every = st.list_binaries()
        if not every:
            return (f"error no_binary: project '{proj}' has no binaries. "
                    "Call open_binary with a file path.")
        if len(every) > 1:
            return (f"error ambiguous_binary: project '{proj}' has {len(every)} binaries "
                    f"({', '.join(x.name for x in every)}). Pass binary=<name>.")
        b = every[0]
    if require_ready:
        err = ix.not_ready_error(proj, st, b)
        if err:
            return err
    return Bound(proj, st, b)


def budget_for(ctx: ServerContext, budget: int = 0) -> int:
    d = ctx.config.defaults
    default = int(d.get("token_budget") or 2000)
    cap = int(d.get("max_budget") or 8000)
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
