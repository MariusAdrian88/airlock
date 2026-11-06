"""dataflow set: trace_values, switch_tables, constants (decompiler p-code, worker ops in dataflow.py).

Compact text, one item per line, cut to the token budget with a cursor. Dirty-role tools: they return
decompiler-derived data and addresses.
"""

from __future__ import annotations

from airlock.server import targets as tg
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError, worker_error
from airlock.server.registry import tool
from airlock.server.tools.common import Bound, bind_many, budget_for
from airlock.worker.protocol import WorkerError


def _page(lines: list[str], bud: int, name: str, args: dict, cursor: str) -> str:
    if cursor:
        try:
            return resume_lines(cursor, bud, "code", tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, "code", tool=name, args=args)[0]


def _function(ctx: ServerContext, binary: str, target: str):
    ft = tg.resolve_target(ctx, binary, target, (tg.FUNCTION,))
    if isinstance(ft, str):
        return ft
    assert isinstance(ft, tg.FunctionTarget)
    bd, fn = ft.bound, ft.fn
    if fn.is_external or bd.binary.format == "dotnet":
        return f"error not_native: '{fn.qualified_name}' has no native code to analyse."
    return bd, fn, ft.any_note


def _call(ctx: ServerContext, bd: Bound, op: str, args: dict, timeout: int = 600) -> dict | str:
    ix = ctx.indexer
    try:
        ix.ensure_open(bd.project)
        return ctx.worker.request(op, {"program": ix.program_of(bd.store, bd.binary), **args}, timeout=timeout)
    except IndexerError as e:
        return e.message
    except WorkerError as e:
        return worker_error(e)


# ── switch_tables ──────────────────────────────────────────────────────────

def _ranges(values: list[int]) -> str:
    vals = sorted({v - (1 << 32) if v >= 0x80000000 else v for v in values})
    out, i = [], 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[j + 1] == vals[j] + 1:
            j += 1
        out.append(str(vals[i]) if i == j else f"{vals[i]}..{vals[j]}" if j > i + 1 else f"{vals[i]},{vals[j]}")
        i = j + 1
    return ",".join(out)


@tool("switch_tables", "Show the switch tables the decompiler recovered in a function: case values to target addresses.")
def switch_tables(ctx: ServerContext, function: str = "", binary: str = "", cursor: str = "",
                  budget: int = 0) -> str:
    args = {"binary": binary, "function": function}
    if cursor:
        return _page([], budget_for(ctx, budget), "switch_tables", args, cursor)
    got = _function(ctx, binary, function)
    if isinstance(got, str):
        return got
    bd, fn, note = got
    bud = budget_for(ctx, budget)
    r = _call(ctx, bd, "switch_tables", {"entry": fn.entry})
    if isinstance(r, str):
        return r
    lines = [f"{fn.qualified_name} {bd.addr(fn.entry)}" + (f" ({note})" if note else "")]
    if not r["switches"]:
        lines.append("no switch table recovered (compare chains and tables the decompiler did not resolve are not listed).")
    for sw_addr, pairs, default, ncases in r["switches"]:
        lines.append(f"switch at {bd.addr(sw_addr)}: {ncases} entries")
        by_t: dict[int, list[int]] = {}
        for lab, tgt in pairs:
            by_t.setdefault(tgt, []).append(lab)
        for tgt, labs in sorted(by_t.items(), key=lambda kv: min(kv[1])):
            lines.append(f"  case {_ranges(labs)} -> {bd.addr(tgt)}")
        if default is not None:
            lines.append(f"  default -> {bd.addr(default)}")
    return fit_lines(lines, bud, "code", tool="switch_tables", args=args)[0]


# ── trace_values ───────────────────────────────────────────────────────────

@tool("trace_values", "Trace a variable or parameter of a function through decompiler def-use chains and into callees.")
def trace_values(ctx: ServerContext, function: str = "", variable: str = "", param: int = 0, depth: int = 2,
                 binary: str = "", cursor: str = "", budget: int = 0) -> str:
    args = {"binary": binary, "function": function, "variable": variable, "param": param, "depth": depth}
    if cursor:
        return _page([], budget_for(ctx, budget), "trace_values", args, cursor)
    if not variable.strip() and param < 1:
        return ("error bad_args: needs variable= (a name from the decompiled C, e.g. local_10 or iVar2) or "
                "param= (1 for the first parameter).")
    if not 0 <= depth <= 5:
        return "error bad_args: depth must be 0 to 5."
    got = _function(ctx, binary, function)
    if isinstance(got, str):
        return got
    bd, fn, note = got
    bud = budget_for(ctx, budget)
    r = _call(ctx, bd, "trace_values", {"entry": fn.entry, "variable": variable.strip() or None,
                                        "param": param or None, "depth": depth})
    if isinstance(r, str):
        return r
    what = variable.strip() or f"param {param}"
    lines = [f"{what} in {fn.qualified_name} {bd.addr(fn.entry)}" + (f" ({note})" if note else "")]
    for level, kind, addr, text in r["rows"]:
        where = f"{bd.addr(addr)} " if addr is not None else ""
        lines.append("  " * (level + 1) + f"{kind} {where}{text}")
    if len(r["rows"]) == 0:
        lines.append("  no definition or use found")
    if r.get("truncated"):
        lines.append(f"… trace cut at the line limit (depth {depth})")
    return fit_lines(lines, bud, "code", tool="trace_values", args=args)[0]


# ── constants ──────────────────────────────────────────────────────────────

def parse_value(text: str) -> int | None:
    t = text.strip().lower().replace("_", "")
    try:
        return int(t, 16) if t.startswith(("0x", "-0x")) else int(t, 10)
    except ValueError:
        return None


@tool("constants", "Find the functions that use an immediate constant such as a magic number or a record tag.")
def constants(ctx: ServerContext, value: str = "", limit: int = 30, binary: str = "",
              cursor: str = "", budget: int = 0) -> str:
    args = {"binary": binary, "value": str(value), "limit": limit}
    if cursor:
        return _page([], budget_for(ctx, budget), "constants", args, cursor)
    v = parse_value(str(value))
    if v is None:
        return "error bad_args: value must be a number like 0x4d5a or 1234."
    if abs(v) < 0x80:
        return "error bad_args: values below 0x80 are encoded in one byte and occur in every function."
    if limit < 1:
        return "error bad_args: limit must be at least 1."
    got = bind_many(ctx, binary)
    if isinstance(got, str):
        return got
    bounds = [bd for bd in got[0] if bd.binary.format != "dotnet"]
    if not bounds:
        return "error not_native: no native binary to search."
    bud = budget_for(ctx, budget)
    several = len(bounds) > 1
    lines: list[str] = []
    for bd in bounds:
        r = _call(ctx, bd, "constants", {"value": v, "limit": limit})
        if isinstance(r, str):
            return r
        pre = f"{bd.binary.name}!" if several else ""
        for entry, n, first in r["rows"]:
            if entry == -1:
                lines.append(f"{pre}(no function) {bd.addr(first)} uses {n}")
                continue
            fn = bd.store.function_at(bd.binary.id, entry)
            nm = fn.qualified_name if fn is not None else "?"
            lines.append(f"{pre}{nm} {bd.addr(entry)} uses {n} first {bd.addr(first)}")
    if not lines:
        return f"no function uses {hex(v)} as an immediate."
    return fit_lines([f"{hex(v)} used by {len(lines)} functions", *lines], bud, "code",
                     tool="constants", args=args, max_lines=limit + 1, page=limit)[0]
