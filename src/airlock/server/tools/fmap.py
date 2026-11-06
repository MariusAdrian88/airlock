"""fmap set: function_map, cluster_label (dirty sessions only). DESIGN 4 "Function map (subsystems)".

Subsystem clusters over the call graph; every line carries the identifiers for the next call.
"""

from __future__ import annotations

from airlock.projects import ProjectPaths
from airlock.server import clusters as cl
from airlock.server.budget import CursorError, estimate_tokens, fit_lines, footer, resume_lines
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server import targets as tg
from airlock.server.tools.common import budget_for

MAX_MEMBER_LINES = 500


def _session(ctx: ServerContext) -> ProjectPaths | str:
    pp = ctx.session.project
    if pp is None:
        return "error unbound: no project is open."
    return pp


def _cost(line: str) -> int:
    return estimate_tokens(line + "\n", "prose")


def _page(lines: list[str], head: int, limit: int, budget: int, args: dict) -> str:
    """fit_lines, with at most ``limit`` entry lines after ``head`` header lines on this page."""
    if limit < 1 or len(lines) - head <= limit:
        return fit_lines(lines, budget, "prose", tool="function_map", args=args)[0]
    need = (sum(_cost(x) for x in lines[:head + limit])
            + estimate_tokens(footer(99999, "c_0000") + "\n", "prose"))
    return fit_lines(lines, min(budget, need), "prose", tool="function_map", args=args)[0]


def _have(cs: cl.ClusterSet) -> str:
    ids = [c.id for c in cl.ordered(cs)]
    return ", ".join(ids[:12]) + (f", … {len(ids) - 12} more" if len(ids) > 12 else "")


def _import_scope(cs: cl.ClusterSet, tr: tg.ImportTarget):
    """Scope of an import: the clusters that contain its callers."""
    near: dict[str, int] = {}
    for _bd, f in tg.import_callers(tr, 2000):
        c = cs.of((f.binary_id, f.space, f.entry))
        if c is not None:
            near[c.id] = near.get(c.id, 0) + 1
    if not near:
        return None, None, [], tg.err(
            "not_clustered", f"no clustered function calls {tr.label}")
    head = [f"{tr.label} is called from " + ", ".join(
        f"{k} ({v} callers)" for k, v in sorted(near.items(), key=lambda kv: (-kv[1], kv[0])))]
    return (lambda c: c.id in near), None, head, None


def _scope_filter(ctx: ServerContext, pp: ProjectPaths, cs: cl.ClusterSet, scope: str):
    """(predicate on Cluster | None, member-binary id | None, header lines, error | None)."""
    st = ctx.indexer.store(pp.name)
    low = scope.strip().lower()
    try:
        feat = st.get_feature(low)
    except Exception:  # noqa: BLE001  no feature tables
        feat = None
    if feat is not None:
        return (lambda c: low in c.features), None, [], None
    bins = [b for b in st.list_binaries() if b.name.lower() == low]
    if not bins:
        bins = [b for b in st.find_binaries(scope) if b.id in cs.binaries] if "!" not in scope else []
        bins = bins if len(bins) == 1 else []
    if bins:
        bid = bins[0].id
        return (lambda c: any(m.key[0] == bid for m in c.members)), bid, [], None
    tr = tg.resolve_target(ctx, "", scope, (tg.FUNCTION, tg.IMPORT))
    if isinstance(tr, str):
        return None, None, [], tr
    if isinstance(tr, tg.ImportTarget):
        return _import_scope(cs, tr)
    assert isinstance(tr, tg.FunctionTarget)
    bound, fn = tr.bound, tr.fn
    key = (fn.binary_id, fn.space, fn.entry)
    own = cs.of(key)
    if own is None:         # a thunk, external or runtime function: scope by its callers' clusters
        by: dict[str, int] = {}
        for f in bound.store.callers(fn):
            c = cs.of((f.binary_id, f.space, f.entry))
            if c is not None:
                by[c.id] = by.get(c.id, 0) + 1
        if not by:
            return None, None, [], (f"error not_clustered: {fn.qualified_name} is a thunk, external or in a "
                                    "runtime binary, and no clustered function calls it.")
        head = [f"{fn.qualified_name} is not clustered (thunk, external or runtime); called from "
                + ", ".join(f"{k} ({v} callers)" for k, v in sorted(by.items(), key=lambda kv: (-kv[1], kv[0])))]
        return (lambda c: c.id in by), None, head, None
    near: dict[str, list[int]] = {}
    for i, lst in enumerate((bound.store.callers(fn), bound.store.callees(fn))):
        for f in lst:
            c = cs.of((f.binary_id, f.space, f.entry))
            if c is not None and c.id != own.id:
                near.setdefault(c.id, [0, 0])[i] += 1
    head = [f"{fn.qualified_name} ({bound.addr(fn.entry, fn.space)}) is in {own.id} {own.label}".rstrip()
            + (f"; neighbours: " + ", ".join(f"{k} ({v[0]} callers, {v[1]} callees)"
                                             for k, v in sorted(near.items())) if near else "")]
    ids = {own.id, *near}
    return (lambda c: c.id in ids), None, head, None


@tool("function_map", "List the subsystem clusters of the program (scope narrows by feature, binary "
                      "or function; runtime library clusters need include_runtime) or, with cluster=C3, "
                      "the functions of one subsystem.")
def function_map(ctx: ServerContext, scope: str = "", cluster: str = "", limit: int = 30,
                 cursor: str = "", budget: int = 0, include_runtime: bool = False) -> str:
    bud = budget_for(ctx, budget)
    args = {"scope": scope, "cluster": cluster, "include_runtime": include_runtime}
    if cursor:
        try:
            return resume_lines(cursor, bud, "prose", tool="function_map", args=args)[0]
        except CursorError as e:
            return e.message
    pp = _session(ctx)
    if isinstance(pp, str):
        return pp
    cs = cl.get_clusters(ctx, pp.name)
    if not cs.clusters:
        return "no subsystem map yet: no analysed binary outside the runtime group."
    pred, member_bin, head, err = None, None, [], None
    if scope.strip():
        pred, member_bin, head, err = _scope_filter(ctx, pp, cs, scope)
        if err:
            return err
    if cluster.strip():
        c = cs.get(cluster)
        if c is None:
            return f"error not_found: no cluster '{cluster}' (have: {_have(cs)})."
        st = ctx.indexer.store(pp.name)
        ev = cl.Evidence(st)
        members = [m for m in c.ranked() if member_bin is None or m.key[0] == member_bin]
        shown = members[:MAX_MEMBER_LINES]
        top = f"{c.id} {c.label}".rstrip() + f": {len(members)} fns ({c.named} named)"
        if member_bin is not None:
            top += f" in {cs.bin_name(member_bin)}"
        lines = [top]
        for m in shown:
            e = ev.of(m.key[0], m.fid)
            lines.append(f"[{cs.bin_name(m.key[0])}] {m.qname} {cs.addr(m)} callers {m.callers} "
                         f"callees {m.callees}" + (f"  evidence: {e}" if e else ""))
        if len(members) > len(shown):
            lines.append(f"… {len(members) - len(shown)} more members not listed (lowest importance).")
        return _page(lines, 1, int(limit), bud, args)
    rows = [c for c in cl.ordered(cs) if pred is None or pred(c)]
    if not rows:            # widen: the whole map answers better than nothing
        rows = list(cl.ordered(cs))
        head = [f"(no subsystem matches scope '{scope.strip()}': whole map)"]
    hidden = [] if include_runtime else [c for c in rows if c.runtime]
    if hidden:
        rows = [c for c in rows if not c.runtime]
    head = [cl.coverage_line(cs)] + head
    lines = head + [cl.cluster_line(cs, c) for c in rows]
    if hidden:
        lines.append(f"{len(hidden)} runtime clusters ({sum(c.total for c in hidden)} fns) hidden: "
                     + ", ".join(c.id for c in hidden[:8]) + (", …" if len(hidden) > 8 else ""))
    return _page(lines, len(head), int(limit), bud, args)


@tool("cluster_label", "Name a subsystem cluster (empty label clears it); the name survives recomputation.")
def cluster_label(ctx: ServerContext, cluster: str, label: str = "") -> str:
    pp = _session(ctx)
    if isinstance(pp, str):
        return pp
    cs = cl.get_clusters(ctx, pp.name)
    c = cs.get(cluster)
    if c is None:
        return f"error not_found: no cluster '{cluster}' (have: {_have(cs)})."
    text = " ".join(label.split())
    if len(text) > cl.MAX_LABEL:
        return f"error too_long: label has {len(text)} characters, the limit is {cl.MAX_LABEL}."
    cl.set_label(pp, cs, c.id, text)
    if not text:
        return f"{c.id} label cleared (auto label: {c.auto_label})."
    return f"{c.id} labeled \"{text}\" ({c.total} fns)."
