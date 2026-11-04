"""Shared call-graph access (DESIGN 4 "Graph view: paths and export"). Server side, no Ghidra.

One directed call graph over the non-thunk, non-external functions of the ready non-runtime
binaries. Thunks and import slots collapse onto their target (in-binary jump target or
cross-binary xedge target). Calls to imports that no project binary provides end in an import
node ``DLL!Name``. Every edge keeps its call-site addresses. The clusters (``clusters.py``) and
the ``path`` / ``graph_export`` tools read the same structure.

Node numbering: ``0..n-1`` functions, ``n..n+m-1`` import nodes (sinks).
"""

from __future__ import annotations

import hashlib
import heapq
import math
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Callable

from airlock.index.store import CODE_EDGES, CODE_SQL, GRAPH_EDGES, Store
from airlock.projects import ProjectPaths, read_manifest
from airlock.server.selectors import fmt_addr, parse_address, split_binary_target

CALL_KINDS = GRAPH_EDGES   # call edges plus fnptr (call through a pointer)
HUB_PERCENT = 0.01
HUB_MIN_CALLERS = 20
MAX_SITES = 8
MAX_ENDPOINT = 2000
MAX_STRINGS = 200

# Fallback API-prefix table, used only when airlock.server.features cannot be imported.
_LOCAL_PREFIX: tuple[tuple[str, str], ...] = (
    ("CreateFile", "file-io"), ("ReadFile", "file-io"), ("WriteFile", "file-io"),
    ("fopen", "file-io"), ("fread", "file-io"), ("fwrite", "file-io"), ("FindFirstFile", "file-io"),
    ("Reg", "config"), ("GetPrivateProfile", "config"), ("WritePrivateProfile", "config"),
    ("socket", "network"), ("connect", "network"), ("send", "network"), ("recv", "network"),
    ("WSA", "network"), ("Internet", "network"), ("CreateWindow", "ui"), ("DialogBox", "ui"),
    ("gl", "graphics"), ("BitBlt", "graphics"), ("DeviceIoControl", "hardware"),
    ("LoadLibrary", "plugins"), ("GetProcAddress", "plugins"), ("Crypt", "licensing"),
)

try:  # another module owns the real tables
    from airlock.server import features as _fx
except Exception:  # noqa: BLE001
    _fx = None


def api_category(name: str | None) -> str | None:
    if not name:
        return None
    if _fx is not None:
        try:
            return _fx.api_feature(name)
        except Exception:  # noqa: BLE001
            pass
    n = name
    for p in ("__imp_", "_imp__", "imp_"):
        if n.startswith(p):
            n = n[len(p):]
    n = n.lstrip("_").split("@", 1)[0]
    for prefix, cat in _LOCAL_PREFIX:
        if n.startswith(prefix):
            return cat
    return None


def string_categories(value: str) -> list[str]:
    if _fx is not None:
        try:
            return list(_fx.string_features(value))
        except Exception:  # noqa: BLE001
            return []
    return []


# -- data model ------------------------------------------------------------------------------

ImportKey = tuple[str, str]       # (dll stem upper, import name)


def dll_stem(dll: str | None) -> str:
    if not dll:
        return ""
    base = PurePosixPath(dll.replace("\\", "/")).name
    low = base.lower()
    for ext in (".dll", ".exe", ".ocx", ".drv", ".sys", ".cpl"):
        if low.endswith(ext):
            base = base[: -len(ext)]
            break
    return base.upper()


def norm_import(name: str) -> str:
    """Lowercase import name without ``__imp_`` / leading underscores / ``@N`` decoration."""
    n = name.strip()
    low = n.lower()
    for p in ("__imp__", "__imp_", "_imp__", "imp_"):
        if low.startswith(p):
            n = n[len(p):]
            break
    return n.lstrip("_").split("@", 1)[0].lower()


def import_label(key: ImportKey) -> str:
    return f"{key[0]}!{key[1]}" if key[0] else key[1]


@dataclass
class CallGraph:
    nodes: list[tuple[int, str, int, int]]             # bid, space, entry, fid
    info: list[tuple[str, str, str | None]]            # name, state, namespace
    directed: dict[tuple[int, int], int]               # function -> function call counts
    cats: dict[int, Counter]
    sites: dict[tuple[int, int], list[int]] = field(default_factory=dict)   # call-site addresses
    imports: list[ImportKey] = field(default_factory=list)                  # import node k = n + k
    imp_directed: dict[tuple[int, int], int] = field(default_factory=dict)  # function -> import node
    import_resolved: dict[ImportKey, set[int]] = field(default_factory=dict)
    import_table: dict[ImportKey, set[int]] = field(default_factory=dict)   # every import -> binary ids
    binaries: dict[int, tuple[str, int]] = field(default_factory=dict)      # id -> (name, pointer size)
    index: dict[tuple[int, str, int], int] = field(default_factory=dict)
    node_of_fid: dict[tuple[int, int], int] = field(default_factory=dict)
    ptr_only: set[tuple[int, int]] = field(default_factory=set)             # hops that exist only via fnptr
    _adj: list[list[int]] | None = None
    _names: dict[str, list[int]] | None = None

    @property
    def n(self) -> int:
        return len(self.nodes)

    @property
    def total(self) -> int:
        return len(self.nodes) + len(self.imports)

    def is_import(self, v: int) -> bool:
        return v >= len(self.nodes)

    def qname(self, v: int) -> str:
        nm, _st, ns = self.info[v]
        return f"{ns}::{nm}" if ns else nm

    def bin_name(self, bid: int) -> str:
        return self.binaries.get(bid, ("?", 4))[0]

    def addr(self, v: int) -> str:
        bid, space, entry, _fid = self.nodes[v]
        return fmt_addr(entry, self.binaries.get(bid, ("?", 4))[1], space)

    def site(self, a: int, b: int) -> int | None:
        s = self.sites.get((a, b))
        return s[0] if s else None

    def site_addr(self, a: int, s: int) -> str:
        bid = self.nodes[a][0]
        return fmt_addr(s, self.binaries.get(bid, ("?", 4))[1], "ram")

    @property
    def adj(self) -> list[list[int]]:
        if self._adj is None:
            out: list[set[int]] = [set() for _ in range(self.total)]
            for (a, b) in self.directed:
                out[a].add(b)
            for (a, b) in self.imp_directed:
                out[a].add(b)
            self._adj = [sorted(x) for x in out]
        return self._adj

    def by_name(self) -> dict[str, list[int]]:
        if self._names is None:
            d: dict[str, list[int]] = {}
            for v in range(self.n):
                nm, _s, ns = self.info[v]
                d.setdefault(nm, []).append(v)
                if ns:
                    d.setdefault(f"{ns}::{nm}", []).append(v)
            self._names = d
        return self._names


# -- construction ----------------------------------------------------------------------------

def build_graph(st: Store, bids: list[int]) -> CallGraph:
    """Read functions and edges of the binaries and build the collapsed directed call graph."""
    fns: dict[int, dict[int, tuple[str, int, bool, bool]]] = {}
    fname: dict[tuple[int, int], str] = {}
    nodes: list[tuple[int, str, int, int]] = []
    info: list[tuple[str, str, str | None]] = []
    node_of: dict[tuple[int, int], int] = {}
    by_entry: dict[tuple[int, int], int] = {}
    ext_ns: dict[tuple[int, int], str | None] = {}
    for bid in bids:
        d: dict[int, tuple[str, int, bool, bool]] = {}
        for r in st.db.execute(
                "SELECT id, space, entry, name, name_state, namespace, is_thunk, is_external "
                "FROM function WHERE binary_id=? ORDER BY space, entry", (bid,)):
            d[r["id"]] = (r["space"], r["entry"], bool(r["is_thunk"]), bool(r["is_external"]))
            if r["is_external"]:
                ext_ns[(bid, r["id"])] = r["namespace"]
            fname[(bid, r["id"])] = r["name"]
            if r["space"] == "ram":
                by_entry[(bid, r["entry"])] = r["id"]
            if not r["is_thunk"] and not r["is_external"]:
                node_of[(bid, r["id"])] = len(nodes)
                nodes.append((bid, r["space"], r["entry"], r["id"]))
                info.append((r["name"], r["name_state"], r["namespace"]))
        fns[bid] = d
    xedge: dict[tuple[int, int], list[tuple[int, int]]] = {}
    dyn_edges: list[tuple[int, int, int, int]] = []
    try:
        for r in st.db.execute("SELECT src_binary, src_addr, dst_binary, dst_entry, kind FROM xedge "
                               "ORDER BY src_binary, src_addr, dst_binary, dst_entry"):
            if r["kind"] in ("dynamic", "dynlib"):   # function to function: added as edges below
                if r["kind"] == "dynamic" and r["src_binary"] in fns and r["dst_binary"] in fns:
                    dyn_edges.append((r["src_binary"], r["src_addr"], r["dst_binary"], r["dst_entry"]))
                continue
            if r["src_binary"] in fns and r["dst_binary"] in fns:
                xedge.setdefault((r["src_binary"], r["src_addr"]), []).append(
                    (r["dst_binary"], r["dst_entry"]))
    except Exception:  # noqa: BLE001  schema without xedge
        pass

    cats: dict[int, Counter] = {}
    raw: list[tuple[int, int, int, int, int]] = []     # bid, src node, dst fid or -1, dst addr, site
    ptr_keys: set[tuple[int, int, int]] = set()        # (bid, site, dst addr) of fnptr edges
    ptr_pairs: set[tuple[int, int]] = set()
    call_pairs: set[tuple[int, int]] = set()
    thunk_out: dict[tuple[int, int], list[tuple[int, int]]] = {}
    imp_by_addr: dict[int, dict[int, ImportKey]] = {}
    imp_by_name: dict[int, dict[str, ImportKey]] = {}
    imp_by_norm: dict[int, dict[str, ImportKey]] = {}
    import_table: dict[ImportKey, set[int]] = {}
    for bid in bids:
        d = fns[bid]
        api_cat: dict[int, str] = {}
        imp_names: set[str] = set()
        by_addr = imp_by_addr.setdefault(bid, {})
        by_name = imp_by_name.setdefault(bid, {})
        by_norm = imp_by_norm.setdefault(bid, {})
        for r in st.db.execute("SELECT dll, name, address FROM import WHERE binary_id=?", (bid,)):
            c = api_category(r["name"])
            if r["name"]:
                imp_names.add(r["name"])
                key = (dll_stem(r["dll"]), r["name"])
                by_name.setdefault(r["name"], key)
                by_norm.setdefault(norm_import(r["name"]), key)
                import_table.setdefault(key, set()).add(bid)
                if r["address"] is not None:
                    by_addr.setdefault(r["address"], key)
            if c and r["address"] is not None:
                api_cat[r["address"]] = c
        for fid, (space, entry, thunk, _ext) in d.items():
            if thunk and space == "ram":
                nm = fname[(bid, fid)]
                if nm in imp_names:
                    c = api_category(nm)
                    if c:
                        api_cat[entry] = c
        strings: dict[int, str] | None = None
        if _fx is not None:
            strings = {r["address"]: r["value"] for r in st.db.execute(
                "SELECT address, value FROM string WHERE binary_id=?", (bid,))}
        str_cache: dict[int, list[str]] = {}
        thunk_ids = {fid for fid, v in d.items() if v[2]}
        for r in st.db.execute(
                "SELECT src_fn, src_addr, dst_fn, dst_addr, kind FROM edge "
                "WHERE binary_id=? AND src_fn IS NOT NULL", (bid,)):
            sf, df, da, kind = r["src_fn"], r["dst_fn"], r["dst_addr"], r["kind"]
            is_call = kind in CALL_KINDS
            if sf in thunk_ids:
                if is_call:
                    thunk_out.setdefault((bid, sf), []).append((da, -1 if df is None else df))
                continue
            sn = node_of.get((bid, sf))
            if sn is None:
                continue
            cat = api_cat.get(da)
            if cat:
                cats.setdefault(sn, Counter())[cat] += 1
            elif not is_call and strings is not None:
                v = strings.get(da)
                if v is not None:
                    sc = str_cache.get(da)
                    if sc is None:
                        sc = str_cache[da] = string_categories(v)
                    for c in sc:
                        cats.setdefault(sn, Counter())[c] += 1
            if is_call:
                if kind == "fnptr":
                    ptr_keys.add((bid, r["src_addr"], da))
                raw.append((bid, sn, -1 if df is None else df, da, r["src_addr"]))

    memo: dict[tuple[int, int], int | None] = {}

    def resolve(bid: int, fid: int, addr: int, depth: int) -> int | None:
        if depth > 8:
            return None
        if fid >= 0:
            f = fns[bid].get(fid)
            if f is None or f[3]:
                return None
            if not f[2]:
                return node_of.get((bid, fid))
            return resolve_thunk(bid, fid, depth)
        return via_x(bid, addr, depth)

    def via_x(bid: int, addr: int, depth: int) -> int | None:
        for db_, de in xedge.get((bid, addr), ()):
            t = by_entry.get((db_, de))
            if t is None:
                continue
            r = resolve(db_, t, de, depth + 1)
            if r is not None:
                return r
        return None

    def resolve_thunk(bid: int, fid: int, depth: int) -> int | None:
        key = (bid, fid)
        if key in memo:
            return memo[key]
        memo[key] = None                                # cycle guard
        r = via_x(bid, fns[bid][fid][1], depth + 1)
        if r is None:
            for da, df in sorted(thunk_out.get(key, ())):
                if df == fid:
                    continue
                r = resolve(bid, df, da, depth + 1)
                if r is not None:
                    break
        memo[key] = r
        return r

    def import_of(bid: int, fid: int, addr: int, depth: int = 0) -> ImportKey | None:
        """The import a call target stands for (slot address, import thunk or external)."""
        if depth > 4:
            return None
        if fid < 0:
            return imp_by_addr.get(bid, {}).get(addr)
        f = fns[bid].get(fid)
        if f is None or not (f[2] or f[3]):
            return None
        k = imp_by_name.get(bid, {}).get(fname[(bid, fid)])
        if k is None:
            k = imp_by_norm.get(bid, {}).get(norm_import(fname[(bid, fid)]))
        if k is not None:
            return k
        if f[3] and not f[2]:                           # external the import table does not list
            return (dll_stem(ext_ns.get((bid, fid))), fname[(bid, fid)])
        if f[2]:
            k = imp_by_addr.get(bid, {}).get(f[1])
            if k is not None:
                return k
            for da, df in sorted(thunk_out.get((bid, fid), ())):
                if df == fid:
                    continue
                k = import_of(bid, df, da, depth + 1)
                if k is not None:
                    return k
        return None

    n = len(nodes)
    directed: dict[tuple[int, int], int] = {}
    imp_directed: dict[tuple[int, int], int] = {}
    sites: dict[tuple[int, int], list[int]] = {}
    imports: list[ImportKey] = []
    import_ix: dict[ImportKey, int] = {}
    import_resolved: dict[ImportKey, set[int]] = {}

    def add_site(edge: tuple[int, int], site: int) -> None:
        lst = sites.setdefault(edge, [])
        if site not in lst and len(lst) < MAX_SITES:
            lst.append(site)

    for bid, sn, df, da, site in raw:
        if df >= 0:
            f = fns[bid].get(df)
            if f is not None and not f[2] and not f[3]:
                dn = node_of.get((bid, df))
            else:
                dn = resolve(bid, df, da, 0)
        else:
            dn = resolve(bid, -1, da, 0)
        if dn is not None:
            if dn != sn:
                directed[(sn, dn)] = directed.get((sn, dn), 0) + 1
                add_site((sn, dn), site)
                (ptr_pairs if (bid, site, da) in ptr_keys else call_pairs).add((sn, dn))
            f2 = fns[bid].get(df) if df >= 0 else None
            if f2 is None or f2[2] or f2[3]:
                k = import_of(bid, df, da)
                if k is not None:
                    import_resolved.setdefault(k, set()).add(dn)
            continue
        k = import_of(bid, df, da)
        if k is None:
            continue
        ix = import_ix.get(k)
        if ix is None:
            ix = import_ix[k] = len(imports)
            imports.append(k)
        edge = (sn, n + ix)
        imp_directed[edge] = imp_directed.get(edge, 0) + 1
        add_site(edge, site)

    for sb_, sa_, db_, de_ in dyn_edges:    # LoadLibrary + GetProcAddress links
        sf_, tf_ = by_entry.get((sb_, sa_)), by_entry.get((db_, de_))
        sn_ = node_of.get((sb_, sf_)) if sf_ is not None else None
        dn_ = resolve(db_, tf_, de_, 0) if tf_ is not None else None
        if sn_ is not None and dn_ is not None and sn_ != dn_:
            directed[(sn_, dn_)] = directed.get((sn_, dn_), 0) + 1
            add_site((sn_, dn_), sa_)

    g = CallGraph(nodes, info, directed, cats, sites, imports, imp_directed, import_resolved,
                  import_table)
    g.ptr_only = ptr_pairs - call_pairs
    g.index = {(b, sp, en): i for i, (b, sp, en, _f) in enumerate(nodes)}
    g.node_of_fid = {(b, f): i for i, (b, _sp, _en, f) in enumerate(nodes)}
    for bid in bids:
        b = st.get_binary_by_id(bid)
        g.binaries[bid] = (b.name if b else "?", (b.pointer_size if b else 4) or 4)
    return g


def find_hubs(g: CallGraph) -> list[int]:
    """Utility hubs: top 1% of the functions by distinct callers, at least HUB_MIN_CALLERS."""
    n = len(g.nodes)
    callers = [0] * n
    for (_a, b) in g.directed:
        callers[b] += 1
    k = max(1, math.ceil(n * HUB_PERCENT)) if n else 0
    ranked = sorted(range(n), key=lambda i: (-callers[i], i))[:k]
    return sorted(i for i in ranked if callers[i] >= HUB_MIN_CALLERS)


# -- project access --------------------------------------------------------------------------

def runtime_ids(pp: ProjectPaths, st: Store) -> set[int]:
    try:
        man = read_manifest(pp.manifest)
    except (OSError, ValueError):
        return set()
    files = [f for f in man.get("files") or [] if isinstance(f, dict) and f.get("group") == "runtime"]
    shas = {f.get("sha256") for f in files if f.get("sha256")}
    names = {PurePosixPath(str(f.get("path", "")).replace("\\", "/")).name.lower() for f in files}
    return {b.id for b in st.list_binaries() if b.sha256 in shas or b.name.lower() in names}


def ready_bins(pp: ProjectPaths, st: Store, runtime: set[int] | None = None) -> list[Any]:
    if runtime is None:
        runtime = runtime_ids(pp, st)
    return [b for b in st.list_binaries()
            if b.id not in runtime and st.get_meta(f"status:{b.id}") == "ready"]


def fingerprint(st: Store, bins: list[Any], tag: str) -> str:
    parts: list[str] = [tag]
    for b in sorted(bins, key=lambda x: x.id):
        nf = st.db.execute("SELECT COUNT(*) FROM function WHERE binary_id=?", (b.id,)).fetchone()[0]
        ne = st.db.execute("SELECT COUNT(*) FROM edge WHERE binary_id=?", (b.id,)).fetchone()[0]
        parts.append(f"{b.id}/{b.analysis_profile or ''}/{nf}/{ne}")
    parts.append(f"n{st.db.execute('SELECT COUNT(*) FROM edge WHERE kind=?', ('call_imp',)).fetchone()[0]}"
                 f"/{st.get_meta('link_version') or 0}")           # import-slot normalisation state
    try:
        parts.append(f"x{st.db.execute('SELECT COUNT(*) FROM xedge').fetchone()[0]}")
    except Exception:  # noqa: BLE001
        pass
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


_CACHE: dict[str, tuple[str, CallGraph]] = {}
_CACHE_LOCK = threading.Lock()


def get_graph(pp: ProjectPaths, st: Store) -> CallGraph:
    """The call graph of the project (kept in memory; rebuilt when the fingerprint changes).
    Names are refreshed on every call so renames show without a rebuild."""
    bins = ready_bins(pp, st)
    fp = fingerprint(st, bins, "g2")
    key = str(pp.index_db)
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
    if hit is not None and hit[0] == fp:
        g = hit[1]
    else:
        g = build_graph(st, [b.id for b in bins])
        with _CACHE_LOCK:
            _CACHE[key] = (fp, g)
    _refresh_names(st, g)
    return g


def _refresh_names(st: Store, g: CallGraph) -> None:
    changed = False
    for bid in g.binaries:
        for r in st.db.execute("SELECT id, name, name_state, namespace FROM function WHERE binary_id=?",
                               (bid,)):
            v = g.node_of_fid.get((bid, r["id"]))
            if v is not None:
                new = (r["name"], r["name_state"], r["namespace"])
                if g.info[v] != new:
                    g.info[v] = new
                    changed = True
    if changed:
        g._names = None


# -- endpoints -------------------------------------------------------------------------------

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


_CLUSTER_ID = re.compile(r"^(?:[cm]\d+|util)$", re.I)


def _cands(g: CallGraph, nodes: list[int]) -> str:
    shown = nodes[:8]
    lst = ", ".join(f"{g.bin_name(g.nodes[v][0])}!{g.qname(v)} {g.addr(v)}" for v in shown)
    return lst + (f" (+{len(nodes) - len(shown)} more)" if len(nodes) > len(shown) else "")


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _functions(g: CallGraph, nodes: list[int], extra: Endpoint | None = None) -> Endpoint:
    """A name that matches one or several functions; several are a valid multi-node endpoint."""
    nodes = sorted(set(nodes))
    if extra is not None:
        merged = sorted(set(nodes) | set(extra.nodes))
        return Endpoint("function", merged[:MAX_ENDPOINT], extra.note, extra.desc)
    if len(nodes) == 1:
        return Endpoint("function", nodes)
    nb = len({g.nodes[v][0] for v in nodes})
    return Endpoint("function", nodes[:MAX_ENDPOINT],
                    desc=f"{len(nodes)} functions in {_count(nb, 'binary', 'binaries')}")


def _by_exact(g: CallGraph, name: str, only_bid: int | None) -> list[int]:
    d = g.by_name()
    hit = list(d.get(name, ()))
    if not hit:
        low = name.lower()
        hit = [v for k, vs in d.items() if k.lower() == low for v in vs]
    hit = sorted(set(hit))
    if only_bid is not None:
        hit = [v for v in hit if g.nodes[v][0] == only_bid]
    return hit


def string_match(st: Store, g: CallGraph, text: str) -> tuple[list[int], str]:
    """Functions that reference a string equal to ``text`` (``*``/``?`` glob; else exact, then
    substring). Returns the nodes and how it matched: ``glob``, ``exact`` or ``substring``."""
    if not g.binaries:
        return [], ""
    marks = ",".join("?" * len(g.binaries))
    bids = list(g.binaries)
    rows: list[Any] = []
    how = "exact"
    if "*" in text or "?" in text:
        how = "glob"
        like = "".join("%" if c == "*" else "_" if c == "?" else ("\\" + c if c in "%_\\" else c)
                       for c in text)
        rows = st.db.execute(f"SELECT binary_id, address FROM string WHERE binary_id IN ({marks}) AND "
                             "value LIKE ? ESCAPE '\\' LIMIT ?", (*bids, like, MAX_STRINGS)).fetchall()
    else:
        rows = st.db.execute(f"SELECT binary_id, address FROM string WHERE binary_id IN ({marks}) AND "
                             "value=? LIMIT ?", (*bids, text, MAX_STRINGS)).fetchall()
        if not rows:
            how = "substring"
            esc = "".join("\\" + c if c in "%_\\" else c for c in text)
            rows = st.db.execute(f"SELECT binary_id, address FROM string WHERE binary_id IN ({marks}) AND "
                                 "value LIKE ? ESCAPE '\\' LIMIT ?",
                                 (*bids, f"%{esc}%", MAX_STRINGS)).fetchall()
    out: set[int] = set()
    for r in rows:
        for e in st.db.execute(
                "SELECT DISTINCT src_fn FROM edge WHERE binary_id=? AND dst_addr=? AND src_fn IS NOT NULL "
                f"AND kind NOT IN ({CODE_SQL})", (r["binary_id"], r["address"])):
            v = g.node_of_fid.get((r["binary_id"], e["src_fn"]))
            if v is not None:
                out.add(v)
    return sorted(out), how


def string_nodes(st: Store, g: CallGraph, text: str) -> list[int]:
    return string_match(st, g, text)[0]


def _string_endpoint(st: Store, g: CallGraph, text: str) -> Endpoint | None:
    nodes, how = string_match(st, g, text)
    if not nodes:
        return None
    return Endpoint("string", nodes[:MAX_ENDPOINT],
                    desc=f"string, {how} match, {_count(len(nodes), 'function', 'functions')}")


def _import_keys(g: CallGraph) -> set[ImportKey]:
    return set(g.imports) | set(g.import_resolved)


def _import_endpoint(g: CallGraph, dll: str, name: str, only_bid: int | None = None) -> Endpoint | None:
    """Import node(s) for ``[DLL!]name``: exact (case- and decoration-insensitive), then the A/W
    variants. Every library that provides the import counts. ``None`` when the name is not an
    import of any binary; an Endpoint without nodes when it is imported but never called."""
    stem = dll_stem(dll) if dll else ""
    universe = _import_keys(g) | set(g.import_table)
    normed = {k: norm_import(k[1]) for k in universe}
    base = norm_import(name)
    if not base:
        return None
    variants = [base, base + "a", base + "w"]
    if len(base) > 3 and base[-1] in "aw":
        root = base[:-1]
        variants += [root, root + "a", root + "w"]
    keys: list[ImportKey] = []
    for v in variants:
        keys = sorted(k for k in universe if normed[k] == v and (not stem or k[0] in (stem, ""))
                      and (only_bid is None or only_bid in g.import_table.get(k, ())))
        if keys:
            break
    if not keys:
        return None
    nodes: set[int] = set()
    for k in keys:
        nodes |= g.import_resolved.get(k, set())
        if k in g.imports:
            nodes.add(g.n + g.imports.index(k))
    label = ", ".join(import_label(k) for k in keys[:3]) + (f" +{len(keys) - 3}" if len(keys) > 3 else "")
    typed = name.strip().lower()
    desc = ""
    if len(nodes) > 1 or any(k[1].lower() != typed for k in keys):
        desc = f"import {label}, {_count(len(nodes), 'node', 'nodes')}"
    return Endpoint("import", sorted(nodes)[:MAX_ENDPOINT], label, desc)


def _uncalled(ep: Endpoint, t: str) -> EndpointError:
    return EndpointError(f"error not_found: import {ep.note} exists but no analysed function calls it "
                         f"(or the calls are indirect), so '{t}' cannot end a path. Try a caller "
                         "found with search or xrefs.")


def resolve_endpoint(st: Store, g: CallGraph, text: str,
                     cluster_members: Callable[[str], list[tuple[int, str, int]] | None] | None = None
                     ) -> Endpoint:
    """Map a ``from``/``to`` text to graph nodes. Raises EndpointError with the one-line error.

    A name that matches several functions is a multi-node endpoint (``Endpoint.desc`` says how
    many). Not a function, import, feature or cluster: exact string, then substring."""
    t = text.strip()
    if not t:
        raise EndpointError("error bad_args: empty endpoint. Pass a function, import, string, "
                            "feature key or cluster id.")
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        s = t[1:-1]
        ep = _string_endpoint(st, g, s)
        if ep is None:
            raise EndpointError(f"error not_found: no function references a string matching {t}. "
                                "Use strings(pattern) to find it.")
        return ep
    if len(t) > 3 and t[0] == "<" and ">!" in t:                     # <main.exe>!name
        t = t[1:].replace(">!", "!", 1)
    if _CLUSTER_ID.match(t) and cluster_members is not None:
        keys = cluster_members(t)
        if keys is not None:
            nodes = sorted(g.index[k] for k in keys if k in g.index)
            if not nodes:
                raise EndpointError(f"error not_found: cluster {t} has no functions in the call graph.")
            return Endpoint("cluster", nodes[:MAX_ENDPOINT])
    pre, bare = split_binary_target(st, t)
    only_bid: int | None = None
    if pre:
        only_bid = next((bid for bid, (nm, _p) in g.binaries.items() if nm.lower() == pre.lower()), None)
        if only_bid is None:
            raise EndpointError(f"error not_found: binary '{pre}' is not in the call graph (not ready or "
                                "a runtime binary). Call list_binaries.")
    addr = parse_address(bare)
    if addr is not None:
        return _by_address(st, g, bare, addr, only_bid)
    hits = _by_exact(g, bare, only_bid)
    if pre:
        if hits:
            return _functions(g, hits)
        for r in st.exports_of(only_bid):
            if r["name"] and r["name"].lower() == bare.lower():
                v = g.index.get((only_bid, "ram", r["address"]))
                if v is not None:
                    return Endpoint("function", [v])
        ep = _import_endpoint(g, "", bare, only_bid) or _import_endpoint(g, "", bare)
        if ep is not None:
            if not ep.nodes:
                raise _uncalled(ep, t)
            return ep
        raise EndpointError(f"error not_found: no function or import '{bare}' in {pre}. Use search or "
                            f"pass {pre}!0xaddress.")
    left, sep, right = t.partition("!")
    ep = _import_endpoint(g, left.strip(), right.strip()) if sep and right.strip() else \
        _import_endpoint(g, "", t)
    if ep is not None and ep.nodes:
        return _functions(g, hits, ep) if hits else ep
    if hits:
        return _functions(g, hits)
    if ep is not None:
        raise _uncalled(ep, t)
    try:
        feat = st.get_feature(t.lower())
    except Exception:  # noqa: BLE001  no feature tables
        feat = None
    if feat is not None:
        nodes = sorted({g.index[(r["binary_id"], r["space"], r["entry"])]
                        for r in st.feature_entries(t.lower())
                        if (r["binary_id"], r["space"], r["entry"]) in g.index})
        if not nodes:
            raise EndpointError(f"error not_found: feature {t.lower()} has no entry point in the call "
                                f"graph. feature(key=\"{t.lower()}\") lists them.")
        return Endpoint("feature", nodes[:MAX_ENDPOINT])
    sep_ep = _string_endpoint(st, g, t)
    if sep_ep is not None:
        return sep_ep
    raise EndpointError(f"error not_found: no function, import, feature, cluster or string '{t}'. "
                        "Use search, features or function_map.")


def _by_address(st: Store, g: CallGraph, raw: str, addr: tuple[str, int], only_bid: int | None) -> Endpoint:
    space, value = addr
    found: list[int] = []
    thunk = False
    for bid in g.binaries:
        if only_bid is not None and bid != only_bid:
            continue
        fn = st.function_at(bid, value, space) or st.function_containing(bid, value, space)
        if fn is None:
            continue
        v = g.index.get((bid, fn.space, fn.entry))
        if v is None:
            thunk = True
        else:
            found.append(v)
    if len(found) == 1:
        return Endpoint("function", found)
    if len(found) > 1:
        raise EndpointError(f"error ambiguous: '{raw}' is in {len(found)} binaries: {_cands(g, found)}. "
                            "Retry with binary!address.")
    if thunk:
        raise EndpointError(f"error not_found: {raw} is a thunk or external, not in the call graph. "
                            "Pass the import name or a function it calls.")
    raise EndpointError(f"error not_found: no function at or containing {raw}. Check the address or use search.")


# -- paths -----------------------------------------------------------------------------------

@dataclass
class PathResult:
    paths: list[list[int]]
    via_util: list[bool]
    max_hops: int
    reach: int | None = None        # hops of the shortest path without depth limit (when none found)


def _yen(g: CallGraph, sources: list[int], targets: set[int], want: int, max_depth: int,
         avoid: set[int], deadline: float) -> list[list[int]]:
    S, T = g.total, g.total + 1
    adj = g.adj
    src_sorted = sorted(sources)
    ban_base = frozenset(avoid - set(sources) - targets)

    def nbrs(u: int) -> list[int]:
        if u == S:
            return src_sorted
        out = adj[u] if u < len(adj) else []
        return out + [T] if u in targets else out

    def bfs(start: int, ban: set[int], ban_e: set[tuple[int, int]], budget: int) -> list[int] | None:
        prev: dict[int, int | None] = {start: None}
        frontier = [start]
        depth = 0
        while frontier and depth < budget:
            depth += 1
            nxt: list[int] = []
            for u in frontier:
                for v in nbrs(u):
                    if v in prev or v in ban or v in ban_base or (u, v) in ban_e:
                        continue
                    prev[v] = u
                    if v == T:
                        path = [T]
                        while prev[path[-1]] is not None:
                            path.append(prev[path[-1]])  # type: ignore[arg-type]
                        return path[::-1]
                    nxt.append(v)
            frontier = nxt
        return None

    limit = max_depth + 2
    first = bfs(S, set(), set(), limit)
    if first is None:
        return []
    accepted = [first]
    cand: list[tuple[int, tuple[int, ...]]] = []
    seen = {tuple(first)}
    while len(accepted) < want and time.monotonic() < deadline:
        last = accepted[-1]
        for i in range(len(last) - 1):
            spur = last[i]
            root = last[: i + 1]
            ban_e = {(p[i], p[i + 1]) for p in accepted if len(p) > i + 1 and p[: i + 1] == root}
            tail = bfs(spur, set(root[:-1]), ban_e, limit - i)
            if tail is None:
                continue
            full = tuple(root[:-1] + tail)
            if full not in seen:
                seen.add(full)
                heapq.heappush(cand, (len(full), full))
        if not cand:
            break
        accepted.append(list(heapq.heappop(cand)[1]))
    return [p[1:-1] for p in accepted]


def _reach_hops(g: CallGraph, sources: list[int], targets: set[int]) -> int | None:
    dist = {s: 0 for s in sources}
    frontier = list(dist)
    adj = g.adj
    best = 0
    while frontier:
        nxt = []
        for u in frontier:
            if u in targets:
                return dist[u]
            for v in adj[u]:
                if v not in dist:
                    dist[v] = dist[u] + 1
                    nxt.append(v)
        frontier = nxt
        best += 1
    return None


def find_paths(g: CallGraph, sources: list[int], targets: list[int], want: int, max_depth: int,
               hubs: list[int] | None = None, budget_s: float = 8.0) -> PathResult:
    """Up to ``want`` shortest simple call chains, preferring chains without util hubs; hub chains
    only when no other chain exists (flagged in ``via_util``)."""
    tset = set(targets)
    hub_set = set(find_hubs(g) if hubs is None else hubs)
    deadline = time.monotonic() + budget_s
    paths = _yen(g, sources, tset, want, max_depth, hub_set, deadline)
    flags = [False] * len(paths)
    if not paths and hub_set:
        paths = _yen(g, sources, tset, want, max_depth, set(), deadline)
        ends = set(sources) | tset
        flags = [any(v in hub_set and v not in ends for v in p) for p in paths]
    reach = None
    if not paths:
        reach = _reach_hops(g, sources, tset)
    return PathResult(paths, flags, max_depth, reach)


def path_query(pp: ProjectPaths, st: Store, frm: str, to: str, want: int, max_depth: int,
               g: CallGraph | None = None, cs_fn: Callable[[], Any] | None = None
               ) -> tuple[Endpoint, Endpoint, PathResult]:
    """Resolve both endpoints and find the paths. Raises EndpointError (one-line message)."""
    g = g or get_graph(pp, st)

    def members(cid: str) -> list[tuple[int, str, int]] | None:
        cs = cs_fn() if cs_fn is not None else None
        if cs is None:
            from airlock.server import clusters as cl   # late: clusters imports this module
            cs = cl.clusters_for(pp, st)
        c = cs.get(cid)
        return [m.key for m in c.members] if c is not None else None

    a = resolve_endpoint(st, g, frm, members)
    b = resolve_endpoint(st, g, to, members)
    return a, b, find_paths(g, a.nodes, b.nodes, want, max_depth)
