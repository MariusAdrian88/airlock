"""graph tools (map set, dirty sessions only): path, graph_export. DESIGN 4 "Graph view: paths and export".

``path`` answers "how does A reach B" over the shared call graph (``server/graph.py``) across
binaries; ``graph_export`` writes a Mermaid / DOT / GraphML file for the user to look at.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import Field

from airlock.projects import ProjectPaths
from airlock.server import diagrams as dg
from airlock.server import endpoints as ep
from airlock.server import graph as gr
from airlock.server.budget import CursorError, estimate_tokens, fit_lines, footer, resume_lines
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.tools.common import budget_for

MORE_PATHS = 7           # extra paths computed beyond k, served through the cursor
MAX_K = 10
MAX_DEPTH = 30
_CURSOR = re.compile(r"cursor=(\S+)\s*$")


def _session(ctx: ServerContext) -> ProjectPaths | str:
    pp = ctx.session.project
    if pp is None:
        return "error unbound: no project is open."
    return pp


def _cost(line: str) -> int:
    return estimate_tokens(line + "\n", "prose")


def _step(g: gr.CallGraph, p: list[int], i: int) -> str:
    v = p[i]
    if g.is_import(v):
        line = f"→ import {gr.import_label(g.imports[v - g.n])}"
    else:
        line = f"→ [{g.bin_name(g.nodes[v][0])}] {g.qname(v)} {g.addr(v)}"
    if i:
        s = g.site(p[i - 1], v)
        ptr = (p[i - 1], v) in g.ptr_only
        if s is not None:
            line += f"   {'ref' if ptr else 'call'} at {g.site_addr(p[i - 1], s)}"
        if ptr:
            line += " (via pointer)"
    return line


def _via(res: gr.PathResult, n: int) -> str:
    util = res.via_util[n]
    rt = n < len(res.via_runtime) and res.via_runtime[n]
    return f" [via {'util+runtime' if util and rt else 'util' if util else 'runtime'}]" if util or rt else ""


def _blocks(g: gr.CallGraph, res: gr.PathResult) -> list[list[str]]:
    out = []
    for n, p in enumerate(res.paths):
        head = [] if n == 0 else [f"also {len(p) - 1} hops" + _via(res, n)]
        out.append(head + [_step(g, p, i) for i in range(len(p))])
    return out


@tool("path", "Find the shortest call chains between two points (function, import, quoted string, "
              "feature key or cluster id), across binaries.")
def path(ctx: ServerContext, from_: Annotated[str, Field(alias="from")] = "", to: str = "",
         k: int = 3, max_depth: int = 8, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        try:
            return resume_lines(cursor, bud, "prose", tool="path", args={})[0]
        except CursorError as e:
            return e.message
    pp = _session(ctx)
    if isinstance(pp, str):
        return pp
    frm, dst = from_.strip(), to.strip()
    if not frm or not dst:
        return "error bad_args: from and to are required."
    k = max(1, min(int(k), MAX_K))
    max_depth = max(1, min(int(max_depth), MAX_DEPTH))
    st = ctx.indexer.store(pp.name)
    g = gr.get_graph(pp, st)
    if not g.nodes:
        return "error not_ready: no analysed binary outside the runtime group."
    try:
        a, b, res = ep.path_query(ctx, pp, st, frm, dst, k + MORE_PATHS, max_depth, g)
        used = ""
        if not res.paths and res.reach and res.reach <= MAX_DEPTH:      # a longer chain exists
            max_depth, used = res.reach, f"max_depth {max_depth} -> {res.reach}"
            a, b, res = ep.path_query(ctx, pp, st, frm, dst, k + MORE_PATHS, max_depth, g)
        elif not res.paths and a.kind == "import" and all(g.is_import(v) for v in a.nodes):
            frm, dst, used = dst, frm, "from and to swapped: an import has no callees"
            a, b, res = ep.path_query(ctx, pp, st, frm, dst, k + MORE_PATHS, max_depth, g)
    except ep.EndpointError as e:
        return e.message
    if not res.paths:
        tail = (f"A chain of {res.reach} hops exists." if res.reach
                else "Calls through function pointers are not in the graph.")
        return (f"error no_path: no call chain from {frm} to {dst} within {max_depth} hops"
                + (f" ({used})" if used else "") + f". {tail}")
    blocks = _blocks(g, res)
    total = len(blocks)
    shown = min(k, total)
    first = len(res.paths[0]) - 1
    fd = f" ({a.desc})" if a.desc else ""
    td = f" ({b.desc})" if b.desc else ""
    head = f"path {frm}{fd} → {dst}{td}, {first} hops" + _via(res, 0) + (f" ({used})" if used else "")
    lines = [head] + [ln for blk in blocks for ln in blk]
    upto = 1 + sum(len(blk) for blk in blocks[:shown])
    need = (sum(_cost(x) for x in lines[:upto]) + _cost(footer(99999, "c_0000")))
    text = fit_lines(lines, min(bud, need), "prose", tool="path", args={})[0]
    rows = text.split("\n")
    m = _CURSOR.search(rows[-1])
    if m:
        visible = 1 + sum(1 for r in rows if r.startswith("also "))
        left = total - visible
        rows[0] += (f" ({left} more paths: cursor={m.group(1)})" if left > 0
                    else f" (cut by budget: cursor={m.group(1)})")
    return "\n".join(rows)


@tool("graph_export", "Write a Mermaid, DOT or GraphML graph of binaries, subsystems, one cluster, one "
                      "feature or a path to dirty\\diagrams for the user and return the file path.")
def graph_export(ctx: ServerContext, scope: str, format: str = "mermaid", inline: bool = False,
                 budget: int = 0) -> str:
    pp = _session(ctx)
    if isinstance(pp, str):
        return pp
    fmt = format.strip().lower()
    if fmt not in dg.FORMATS:
        return f"error bad_args: format '{format}' is not one of mermaid, dot, graphml."
    st = ctx.indexer.store(pp.name)
    env = dg.Env(pp, st, ctx)
    try:
        d = dg.diagram_for(env, scope)
    except dg.ScopeError as e:
        return e.message
    except ep.EndpointError as e:
        return e.message
    path_ = dg.write_diagram(pp, scope, fmt, d)
    more = f", {d.hidden} more nodes summarised" if d.hidden else ""
    head = f"wrote {path_} ({fmt}, {len(d.nodes)} nodes, {len(d.edges)} edges{more})"
    if not inline:
        return head
    text = dg.render(d, fmt, fence=False).rstrip("\n")
    if estimate_tokens(head + "\n" + text, "prose") > budget_for(ctx, budget):
        return head + "\ninline omitted: the graph is larger than the response budget."
    return head + "\n" + text
