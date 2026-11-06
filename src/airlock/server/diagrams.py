"""Graph diagrams for the user (DESIGN 4 "Graph view: paths and export"): build a small node/edge
model from the call graph, clusters or features and render it as Mermaid, DOT or GraphML.
Server side, no Ghidra. Files go to ``dirty\\diagrams\\``.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from xml.sax.saxutils import escape as xml_escape
from xml.sax.saxutils import quoteattr

from airlock.index.store import Store
from airlock.projects import ProjectPaths, atomic_write_text
from airlock.server import clusters as cl
from airlock.server import endpoints as ep
from airlock.server import graph as gr

if TYPE_CHECKING:
    from airlock.server.context import ServerContext

log = logging.getLogger("airlock")

MAX_NODES = 150
FORMATS = {"mermaid": "md", "dot": "dot", "graphml": "graphml"}
PATH_DIAGRAM_K = 3


class ScopeError(Exception):
    """Carries a ready-to-print one-line error."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass
class Diagram:
    title: str
    nodes: list[tuple[str, str]] = field(default_factory=list)          # id, label
    edges: list[tuple[str, str, str]] = field(default_factory=list)     # src, dst, label
    directed: bool = True
    hidden: int = 0                                                      # nodes folded into "more"


def cap_diagram(d: Diagram, limit: int = MAX_NODES) -> Diagram:
    """At most ``limit`` nodes: the first ``limit - 1`` stay, the rest become one summary node."""
    if len(d.nodes) <= limit:
        return d
    keep = d.nodes[: limit - 1]
    ids = {i for i, _ in keep}
    hidden = len(d.nodes) - len(keep)
    more = "more"
    merged: dict[tuple[str, str], str] = {}
    for a, b, lab in d.edges:
        a2 = a if a in ids else more
        b2 = b if b in ids else more
        if a2 == b2:
            continue
        key = (a2, b2)
        if key in merged and merged[key].isdigit() and lab.isdigit():
            merged[key] = str(int(merged[key]) + int(lab))
        else:
            merged.setdefault(key, lab)
    return Diagram(d.title, keep + [(more, f"... {hidden} more nodes")],
                   [(a, b, lab) for (a, b), lab in merged.items()], d.directed, hidden)


# -- renderers -------------------------------------------------------------------------------

def _clean(s: str) -> str:
    return " ".join(s.replace("\r", " ").replace("\n", " ").split())


def _mm(s: str) -> str:
    s = _clean(s)
    for ch, rep in (("#", "#35;"), ("&", "#amp;"), ('"', "#quot;"), ("<", "#lt;"), (">", "#gt;"),
                    ("`", "#96;"), ("|", "#124;"), ("{", "#123;"), ("}", "#125;"), ("[", "#91;"),
                    ("]", "#93;"), ("(", "#40;"), (")", "#41;")):
        s = s.replace(ch, rep)
    return s


def to_mermaid(d: Diagram) -> str:
    lines = ["flowchart LR"]
    for nid, lab in d.nodes:
        lines.append(f'  {_mid(nid)}["{_mm(lab)}"]')
    arrow = "-->" if d.directed else "---"
    for a, b, lab in d.edges:
        mid = f"|{_mm(lab)}|" if lab else ""
        lines.append(f"  {_mid(a)} {arrow}{mid} {_mid(b)}")
    return "\n".join(lines) + "\n"


def _mid(nid: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", nid)


def _dq(s: str) -> str:
    return _clean(s).replace("\\", "\\\\").replace('"', '\\"')


def to_dot(d: Diagram) -> str:
    kind, op = ("digraph", "->") if d.directed else ("graph", "--")
    lines = [f'{kind} "{_dq(d.title)}" {{', "  rankdir=LR;", "  node [shape=box];"]
    for nid, lab in d.nodes:
        lines.append(f'  "{_dq(nid)}" [label="{_dq(lab)}"];')
    for a, b, lab in d.edges:
        extra = f' [label="{_dq(lab)}"]' if lab else ""
        lines.append(f'  "{_dq(a)}" {op} "{_dq(b)}"{extra};')
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_graphml(d: Diagram) -> str:
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
           '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
           '  <key id="weight" for="edge" attr.name="label" attr.type="string"/>',
           f'  <graph id="G" edgedefault="{"directed" if d.directed else "undirected"}">']
    for nid, lab in d.nodes:
        out.append(f"    <node id={quoteattr(_clean(nid))}><data key=\"label\">{xml_escape(_clean(lab))}</data></node>")
    for i, (a, b, lab) in enumerate(d.edges):
        data = f'<data key="weight">{xml_escape(_clean(lab))}</data>' if lab else ""
        out.append(f"    <edge id=\"e{i}\" source={quoteattr(_clean(a))} target={quoteattr(_clean(b))}>"
                   f"{data}</edge>")
    out += ["  </graph>", "</graphml>"]
    return "\n".join(out) + "\n"


def render(d: Diagram, fmt: str, fence: bool = True) -> str:
    if fmt == "mermaid":
        body = to_mermaid(d)
        return f"```mermaid\n{body}```\n" if fence else body
    if fmt == "dot":
        return to_dot(d)
    if fmt == "graphml":
        return to_graphml(d)
    raise ValueError(fmt)


def slug(scope: str) -> str:
    s = re.sub(r"[^a-z0-9._]+", "-", scope.lower().replace("->", "-")).strip("-.")
    return (s[:60].strip("-.") or "graph")


def diagram_path(pp: ProjectPaths, scope: str, fmt: str) -> Path:
    return pp.dirty / "diagrams" / f"{slug(scope)}.{FORMATS[fmt]}"


def write_diagram(pp: ProjectPaths, scope: str, fmt: str, d: Diagram, name: str | None = None) -> Path:
    path = diagram_path(pp, name or scope, fmt)
    atomic_write_text(path, render(d, fmt))
    return path


# -- scopes ----------------------------------------------------------------------------------

class Env:
    """Lazy handles on the call graph and clusters of one project."""

    def __init__(self, pp: ProjectPaths, st: Store, ctx: ServerContext | None = None) -> None:
        self.pp, self.st, self.ctx = pp, st, ctx
        self._g: gr.CallGraph | None = None
        self._cs: cl.ClusterSet | None = None

    @property
    def g(self) -> gr.CallGraph:
        if self._g is None:
            self._g = gr.get_graph(self.pp, self.st)
        return self._g

    @property
    def cs(self) -> cl.ClusterSet:
        if self._cs is None:
            self._cs = cl.clusters_for(self.pp, self.st)
        return self._cs


def _short(addr: int) -> str:
    return f"0x{addr:x}"


def _fn_label(g: gr.CallGraph, v: int) -> str:
    if g.is_import(v):
        return "import " + gr.import_label(g.imports[v - g.n])
    pre = f"{g.bin_name(g.nodes[v][0])}!" if len(g.binaries) > 1 else ""
    return f"{pre}{g.qname(v)} {_short(g.nodes[v][2])}"


def _fn_id(v: int) -> str:
    return f"f{v}"


def binaries_diagram(env: Env) -> Diagram:
    bins = env.st.list_binaries()
    d = Diagram("binaries")
    names = {b.id: b.name for b in bins}
    d.nodes = [(f"b{b.id}", b.name) for b in bins]
    try:
        rows = env.st.db.execute(
            "SELECT src_binary, dst_binary, COUNT(DISTINCT src_addr) AS n FROM xedge "
            "GROUP BY src_binary, dst_binary ORDER BY src_binary, dst_binary").fetchall()
    except Exception:  # noqa: BLE001
        rows = []
    d.edges = [(f"b{r['src_binary']}", f"b{r['dst_binary']}", str(r["n"])) for r in rows
               if r["src_binary"] in names and r["dst_binary"] in names]
    return d


def subsystems_diagram(env: Env) -> Diagram:
    cs = env.cs
    if not cs.clusters:
        raise ScopeError("error not_found: no subsystem map yet: no analysed binary outside the runtime "
                         "group.")
    order = cl.ordered(cs)
    pos = {c.id: i for i, c in enumerate(order)}
    d = Diagram("subsystems", directed=False)
    for c in order:
        lab = f"{c.id} {c.label}".rstrip() + f" ({c.total} fns)"
        d.nodes.append((c.id, lab))
    for c in order:
        for k, v in sorted(c.links.items()):
            if k in pos and pos[c.id] < pos[k]:
                d.edges.append((c.id, k, str(v)))
    return d


def cluster_diagram(env: Env, cid: str) -> Diagram:
    c = env.cs.get(cid)
    if c is None:
        have = ", ".join(x.id for x in cl.ordered(env.cs)[:12])
        raise ScopeError(f"error not_found: no cluster '{cid}' (have: {have}).")
    g = env.g
    d = Diagram(f"cluster {c.id}")
    ids: set[int] = set()
    for m in c.ranked():
        v = g.index.get(m.key)
        if v is not None:
            ids.add(v)
            d.nodes.append((_fn_id(v), _fn_label(g, v)))
    for (a, b), w in sorted(g.directed.items()):
        if a in ids and b in ids:
            d.edges.append((_fn_id(a), _fn_id(b), str(w)))
    return d


def feature_diagram(env: Env, key: str) -> Diagram:
    st = env.st
    try:
        feat = st.get_feature(key.lower())
    except Exception:  # noqa: BLE001
        feat = None
    if feat is None:
        have = ", ".join(r["key"] for r in st.db.execute("SELECT key FROM feature ORDER BY key LIMIT 13"))
        raise ScopeError(f"error not_found: no feature '{key}' (have: {have or 'none'}).")
    g, cs = env.g, env.cs
    d = Diagram(f"feature {feat['key']}")
    cl_nodes: dict[str, str] = {}
    members: list[tuple[int, str | None]] = []
    for r in st.feature_entries(feat["key"]):
        k = (r["binary_id"], r["space"], r["entry"])
        v = g.index.get(k)
        if v is None:
            continue
        c = cs.of(k)
        members.append((v, c.id if c else None))
        if c is not None and c.id not in cl_nodes:
            cl_nodes[c.id] = f"{c.id} {c.label}".rstrip()
    d.nodes = [(f"c_{cid}", lab) for cid, lab in sorted(cl_nodes.items())]
    for v, cid in members:
        d.nodes.append((_fn_id(v), _fn_label(g, v)))
        if cid is not None:
            d.edges.append((_fn_id(v), f"c_{cid}", ""))
    return d


def path_diagram(env: Env, frm: str, to: str, k: int = PATH_DIAGRAM_K, max_depth: int = 8) -> Diagram:
    if env.ctx is None:
        raise ScopeError("error unbound: no project is open.")
    try:
        _a, _b, res = ep.path_query(env.ctx, env.pp, env.st, frm, to, k, max_depth, env.g)
    except ep.EndpointError as e:
        raise ScopeError(e.message) from None
    if not res.paths:
        raise ScopeError(f"error no_path: no call chain from {frm} to {to} within {max_depth} hops.")
    g = env.g
    d = Diagram(f"path {frm} to {to}")
    seen: set[int] = set()
    edges: dict[tuple[int, int], str] = {}
    for p in res.paths[:max(1, k)]:
        for i, v in enumerate(p):
            if v not in seen:
                seen.add(v)
                d.nodes.append((_fn_id(v), _fn_label(g, v)))
            if i:
                s = g.site(p[i - 1], v)
                edges.setdefault((p[i - 1], v), _short(s) if s is not None else "")
    d.edges = [(_fn_id(a), _fn_id(b), lab) for (a, b), lab in edges.items()]
    return d


def build_scope(env: Env, scope: str, k: int = PATH_DIAGRAM_K, max_depth: int = 8) -> Diagram:
    """Diagram for a ``graph_export`` scope. Raises ScopeError with the one-line error."""
    s = scope.strip()
    low = s.lower()
    if low == "binaries":
        return binaries_diagram(env)
    if low == "subsystems":
        return subsystems_diagram(env)
    if low.startswith("cluster:"):
        return cluster_diagram(env, s.split(":", 1)[1].strip())
    if low.startswith("feature:"):
        return feature_diagram(env, s.split(":", 1)[1].strip())
    if low.startswith("path:"):
        body = s.split(":", 1)[1]
        parts = re.split(r"->|→", body, maxsplit=1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ScopeError("error bad_args: path scope is path:<from>-><to>. "
                             "Example: path:Main->ReadFile.")
        return path_diagram(env, parts[0].strip(), parts[1].strip(), k, max_depth)
    raise ScopeError(f"error bad_args: unknown scope '{scope}' (scopes: binaries, subsystems, cluster:C3, "
                     "feature:<key>, path:<from>-><to>).")


def diagram_for(env: Env, scope: str, **kw: Any) -> Diagram:
    return cap_diagram(build_scope(env, scope, **kw))


# -- the defaults.mermaid hook ---------------------------------------------------------------

def write_mermaid_set(pp: ProjectPaths, st: Store) -> list[Path]:
    """binaries.md, subsystems.md and feature-<key>.md for every feature with entry points.
    Never raises (a diagram is an extra)."""
    env = Env(pp, st)
    out: list[Path] = []

    def one(scope: str, name: str, build: Any) -> None:
        try:
            out.append(write_diagram(pp, scope, "mermaid", cap_diagram(build()), name=name))
        except Exception as e:  # noqa: BLE001
            log.warning("could not write diagram %s for %s: %s", name, pp.name, e)

    one("binaries", "binaries", lambda: binaries_diagram(env))
    one("subsystems", "subsystems", lambda: subsystems_diagram(env))
    try:
        rows = [r for r in st.feature_stats() if r["n"] > 0]
    except Exception:  # noqa: BLE001
        rows = []
    for r in rows:
        key = r["key"]
        one(f"feature:{key}", f"feature-{key}", lambda key=key: feature_diagram(env, key))
    return out
