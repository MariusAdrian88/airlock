"""Endpoints of the ``path`` tool: the text of ``from`` / ``to`` mapped to call-graph nodes.

Resolution is the shared resolver (``targets.resolve_target``, DESIGN 7.3), so a name means the
same thing here as in ``xrefs`` and ``callgraph``. This module only turns a typed target into
graph nodes. ``path`` aggregates (DESIGN 7.3 rule 8): a name that matches several functions, or a
function and an import, is one multi-node endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from airlock.index.store import CODE_SQL, Store
from airlock.projects import ProjectPaths
from airlock.server import graph as gr
from airlock.server import targets as tg
from airlock.server.context import ServerContext
from airlock.server.graph import MAX_ENDPOINT, CallGraph, norm_import
from airlock.server.selectors import split_binary_target

PATH_KINDS = (tg.FUNCTION, tg.IMPORT, tg.STRING, tg.FEATURE, tg.CLUSTER)


class EndpointError(Exception):
    """Carries a ready-to-print one-line error."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass
class Endpoint:
    kind: str                  # function, import, string, feature, cluster
    nodes: list[int]
    note: str = ""
    desc: str = ""             # shown in the path header when the match is not a plain single function


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _fn_nodes(g: CallGraph, pairs: Any) -> list[int]:
    out = {g.index[(bd.binary.id, f.space, f.entry)] for bd, f in pairs
           if (bd.binary.id, f.space, f.entry) in g.index}
    return sorted(out)


def _import_nodes(g: CallGraph, t: tg.ImportTarget) -> list[int]:
    wanted = {(s, norm_import(n)) for s, n in t.keys}
    norms = {n for _s, n in wanted}
    nodes: set[int] = set()
    for k in set(g.imports) | set(g.import_resolved):
        nk = norm_import(k[1])
        if (k[0], nk) in wanted or (not k[0] and nk in norms):
            nodes |= g.import_resolved.get(k, set())
            if k in g.imports:
                nodes.add(g.n + g.imports.index(k))
    nodes |= set(_fn_nodes(g, t.library))
    return sorted(nodes)


def _import_endpoint(g: CallGraph, t: tg.ImportTarget, typed: str) -> Endpoint:
    nodes = _import_nodes(g, t)
    low = typed.strip().lower()
    desc = ""
    if len(nodes) > 1 or any(n.lower() != low for _s, n in t.keys):
        desc = f"import {t.label}, {_count(len(nodes), 'node', 'nodes')}"
    return Endpoint("import", nodes[:MAX_ENDPOINT], t.label, desc)


def _uncalled(label: str, t: str) -> EndpointError:
    return EndpointError(f"error not_found: import {label} exists but no analysed function calls it "
                         f"(or the calls are indirect), so '{t}' cannot end a path.")


def _string_nodes(g: CallGraph, t: tg.StringTarget) -> list[int]:
    out: set[int] = set()
    for bd, hit in t.matches:
        for e in bd.store.db.execute(
                "SELECT DISTINCT src_fn FROM edge WHERE binary_id=? AND dst_addr=? AND src_fn IS NOT NULL "
                f"AND kind NOT IN ({CODE_SQL})", (bd.binary.id, hit.address)):
            v = g.node_of_fid.get((bd.binary.id, e["src_fn"]))
            if v is not None:
                out.add(v)
    return sorted(out)


_NO_STRING = "error not_found: no function references a string matching {t}."
_NOT_IN_GRAPH = "error not_found: {t} is a thunk, external or runtime function, not in the call graph."


def _remap(msg: str, text: str, quoted: bool) -> str:
    """The resolver's not_found wording, in the terms of ``path``."""
    if not msg.startswith("error not_found:"):
        return msg
    if quoted:
        return _NO_STRING.format(t=text)
    if msg.startswith("error not_found: no function or import named"):
        close = msg.partition("close names: ")[2].rstrip(".")
        return (f"error not_found: no function, import, feature, cluster or string '{text}'."
                + (f" close names: {close}." if close else ""))
    return msg


def _export_node(g: CallGraph, pre: str, name: str, st: Store) -> int | None:
    bid = next((b for b, (nm, _p) in g.binaries.items() if nm.lower() == pre.lower()), None)
    if bid is None:
        return None
    for r in st.exports_of(bid):
        if r["name"] and r["name"].lower() == name.lower():
            return g.index.get((bid, "ram", r["address"]))
    return None


def _follow_stub(ctx: ServerContext, g: CallGraph, r: tg.FunctionTarget, t: str) -> Endpoint | None:
    """A thunk or external row is not a graph node; the import it stands for is. None when the
    name is no import with nodes."""
    if not (r.fn.is_thunk or r.fn.is_external):
        return None
    imp = tg.resolve_target(ctx, r.bound.binary.name, r.fn.name, (tg.IMPORT,))
    if not isinstance(imp, tg.ImportTarget):
        return None
    ep = _import_endpoint(g, imp, t)
    if not ep.nodes:
        return None
    ep.desc = f"import {imp.label}, followed from the thunk"
    return ep


def resolve_endpoint(ctx: ServerContext, st: Store, g: CallGraph, text: str) -> Endpoint:
    """Map a ``from``/``to`` text to graph nodes. Raises EndpointError with the one-line error."""
    t = text.strip()
    if not t:
        raise EndpointError("error bad_args: empty endpoint.")
    quoted = len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'"
    r = tg.resolve_target(ctx, "", t, PATH_KINDS, aggregate=True)
    if isinstance(r, str):
        pre, bare = split_binary_target(st, t)
        if pre and r.startswith("error not_found:"):          # an export under another name
            v = _export_node(g, pre, bare, st)
            if v is not None:
                return Endpoint("function", [v])
        raise EndpointError(_remap(r, t, quoted))
    if isinstance(r, tg.FunctionTarget):
        v = g.index.get((r.bound.binary.id, r.fn.space, r.fn.entry))
        if v is None:
            followed = _follow_stub(ctx, g, r, t)
            if followed is not None:
                return followed
            raise EndpointError(_NOT_IN_GRAPH.format(t=t))
        return Endpoint("function", [v])
    if isinstance(r, tg.MultiFunctionTarget):
        nodes = _fn_nodes(g, r.functions)
        imp = _import_endpoint(g, r.imports, t) if r.imports is not None else None
        merged = sorted(set(nodes) | set(imp.nodes if imp else ()))
        if not merged:
            if imp is not None:
                raise _uncalled(imp.note, t)
            raise EndpointError(_NOT_IN_GRAPH.format(t=t))
        if imp is not None and imp.nodes:
            return Endpoint("function", merged[:MAX_ENDPOINT], imp.note, imp.desc)
        if len(merged) == 1:
            return Endpoint("function", merged)
        nb = len({g.nodes[v][0] for v in merged if v < g.n})
        return Endpoint("function", merged[:MAX_ENDPOINT],
                        desc=f"{len(merged)} functions in {_count(nb, 'binary', 'binaries')}")
    if isinstance(r, tg.ImportTarget):
        ep = _import_endpoint(g, r, t)
        if not ep.nodes:
            raise _uncalled(ep.note, t)
        return ep
    if isinstance(r, tg.StringTarget):
        nodes = _string_nodes(g, r)
        if not nodes:
            raise EndpointError(_NO_STRING.format(t=t))
        return Endpoint("string", nodes[:MAX_ENDPOINT],
                        desc=f"string, {r.how} match, {_count(len(nodes), 'function', 'functions')}")
    if isinstance(r, tg.FeatureTarget):
        nodes = sorted({g.index[(e["binary_id"], e["space"], e["entry"])]
                        for e in st.feature_entries(r.key)
                        if (e["binary_id"], e["space"], e["entry"]) in g.index})
        if not nodes:
            raise EndpointError(f"error not_found: feature {r.key} has no entry point in the call graph.")
        return Endpoint("feature", nodes[:MAX_ENDPOINT])
    if isinstance(r, tg.ClusterTarget):
        nodes = sorted(g.index[m.key] for m in r.cluster.members if m.key in g.index)   # type: ignore[attr-defined]
        if not nodes:
            raise EndpointError(f"error not_found: cluster {r.id} has no functions in the call graph.")
        return Endpoint("cluster", nodes[:MAX_ENDPOINT])
    raise EndpointError(f"error bad_target: '{t}' cannot be a path endpoint (endpoints: function, import, "
                        "string, feature key, cluster id).")


def path_query(ctx: ServerContext, pp: ProjectPaths, st: Store, frm: str, to: str, want: int,
               max_depth: int, g: CallGraph | None = None) -> tuple[Endpoint, Endpoint, gr.PathResult]:
    """Resolve both endpoints and find the paths. Raises EndpointError (one-line message)."""
    g = g or gr.get_graph(pp, st)
    a = resolve_endpoint(ctx, st, g, frm)
    b = resolve_endpoint(ctx, st, g, to)
    return a, b, gr.find_paths(g, a.nodes, b.nodes, want, max_depth)
