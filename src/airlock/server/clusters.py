"""Subsystem clusters over the call graph (DESIGN 4 "Function map (subsystems)"). Server side.

Graph: non-thunk, non-external functions of the ready non-runtime binaries; edge weight = number of
call/call_ind/jump edges between two functions (both directions summed). Thunks and import slots
collapse onto their target (in-binary jump target or cross-binary xedge target). Hub utilities
(top 1% by distinct callers, at least ``HUB_MIN_CALLERS``) form the ``util`` group and are left out of
clustering. Algorithm: deterministic multi-level Louvain, pure Python. Clusters under
``MIN_CLUSTER`` members go to a per-binary ``misc`` bucket.

The partition is a derived cache (``cache/clusters.json``, keyed by a fingerprint). Agent labels live in
``cluster_labels.json`` and are re-attached after a recomputation by member overlap (Jaccard).
"""

from __future__ import annotations

import json
import os
import random
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.index.store import Store
from airlock.projects import ProjectPaths, atomic_write_text
from airlock.server import graph as gr
from airlock.server.graph import (  # noqa: F401  re-exported: tests and callers use them from here
    CALL_KINDS, HUB_MIN_CALLERS, HUB_PERCENT, CallGraph, _fx, api_category, build_graph, string_categories,
)
from airlock.server.features import MFC_CLASSES, lib_family
from airlock.server.selectors import fmt_addr

MIN_CLUSTER = 3
ALGO_VERSION = 5   # 2: call_imp edges; 3: library recognition, runtime labels; 4: static-runtime rules, mixed; 5: CRT underscore rule
RUNTIME_SHARE = 0.6     # a cluster with at least this share of library members is a runtime cluster
RUNTIME_PREFIX = "runtime"
LABEL_JACCARD = 0.5
LABELS_FILE = "cluster_labels.json"
CACHE_FILE = "clusters.json"
KEY_FUNCTIONS = 5       # function_map
MAP_KEY_FUNCTIONS = 3   # project map, Subsystems section
MAX_LABEL = 60

_LOCK = threading.Lock()
_LOCKS: dict[str, threading.Lock] = {}

# -- data model ------------------------------------------------------------------------------

Key = tuple[int, str, int]  # binary id, space, entry


@dataclass
class Member:
    key: Key
    name: str = "?"
    name_state: str = "auto"
    namespace: str | None = None
    fid: int = 0
    centrality: int = 0
    callers: int = 0
    callees: int = 0

    @property
    def qname(self) -> str:
        return f"{self.namespace}::{self.name}" if self.namespace else self.name


@dataclass
class Cluster:
    id: str
    kind: str                       # "c" regular, "misc", "util"
    auto_label: str
    members: list[Member]
    links: dict[str, int] = field(default_factory=dict)
    binary: int | None = None       # misc buckets
    agent_label: str = ""
    features: dict[str, int] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.agent_label or self.auto_label

    @property
    def runtime(self) -> bool:
        """Mostly library code (the automatic label starts with ``runtime``)."""
        return self.kind == "c" and self.auto_label.startswith(RUNTIME_PREFIX)

    @property
    def total(self) -> int:
        return len(self.members)

    @property
    def named(self) -> int:
        return sum(1 for m in self.members if m.name_state != "auto")

    def key_functions(self, n: int = KEY_FUNCTIONS) -> list[Member]:
        return self.ranked()[:n]

    def ranked(self) -> list[Member]:
        return sorted(self.members, key=lambda m: (-m.centrality, -m.callers, m.key))


@dataclass
class ClusterSet:
    project: str
    fingerprint: str
    clusters: list[Cluster]
    binaries: dict[int, tuple[str, int]]      # id -> (name, pointer size)
    where: dict[Key, str] = field(default_factory=dict)
    recomputed: bool = False

    def __post_init__(self) -> None:
        if not self.where:
            for c in self.clusters:
                for m in c.members:
                    self.where[m.key] = c.id

    def get(self, cid: str) -> Cluster | None:
        want = cid.strip().lower()
        return next((c for c in self.clusters if c.id.lower() == want), None)

    def of(self, key: Key) -> Cluster | None:
        cid = self.where.get(key)
        return self.get(cid) if cid else None

    def addr(self, m: Member) -> str:
        return fmt_addr(m.key[2], self.binaries.get(m.key[0], ("?", 4))[1], m.key[1])

    def bin_name(self, bid: int) -> str:
        return self.binaries.get(bid, ("?", 4))[0]

    @property
    def multi(self) -> bool:
        return len(self.binaries) > 1


# -- Louvain ---------------------------------------------------------------------------------

def louvain(n: int, edges: dict[tuple[int, int], float], max_levels: int = 4, max_passes: int = 12,
            seed: int = 20240607) -> list[int]:
    """Community id (0..k-1) per node 0..n-1. Deterministic: fixed shuffled visiting order, ties go to
    the lowest community id. ``edges`` maps (a, b) with a < b to a positive weight."""
    adj: list[dict[int, float]] = [dict() for _ in range(n)]
    for (a, b), w in edges.items():
        if a != b:
            adj[a][b] = adj[a].get(b, 0.0) + w
            adj[b][a] = adj[b].get(a, 0.0) + w
    loops = [0.0] * n
    member_of = list(range(n))        # original node -> current-level node
    rng = random.Random(seed)
    for _level in range(max_levels):
        size = len(adj)
        deg = [sum(adj[i].values()) + 2 * loops[i] for i in range(size)]
        m2 = sum(deg)
        if m2 <= 0:
            break
        comm = list(range(size))
        tot = deg[:]
        order = list(range(size))
        rng.shuffle(order)
        improved = False
        for _pass in range(max_passes):
            moved = 0
            for i in order:
                ci = comm[i]
                ki = deg[i]
                w_to: dict[int, float] = {}
                for j, w in adj[i].items():
                    cj = comm[j]
                    w_to[cj] = w_to.get(cj, 0.0) + w
                tot[ci] -= ki
                best = ci
                best_gain = w_to.get(ci, 0.0) - tot[ci] * ki / m2
                for c in sorted(w_to):
                    gain = w_to[c] - tot[c] * ki / m2
                    if gain > best_gain + 1e-12:
                        best, best_gain = c, gain
                tot[best] += ki
                if best != ci:
                    comm[i] = best
                    moved += 1
            if not moved:
                break
            improved = True
        if not improved:
            break
        # renumber communities by first appearance in node order (deterministic)
        remap: dict[int, int] = {}
        for i in range(size):
            remap.setdefault(comm[i], len(remap))
        comm = [remap[c] for c in comm]
        member_of = [comm[x] for x in member_of]
        k = len(remap)
        if k == size:
            break
        nadj: list[dict[int, float]] = [dict() for _ in range(k)]
        nloops = [0.0] * k
        for i in range(size):
            ci = comm[i]
            nloops[ci] += loops[i]
            for j, w in adj[i].items():
                cj = comm[j]
                if ci == cj:
                    nloops[ci] += w / 2.0
                else:
                    nadj[ci][cj] = nadj[ci].get(cj, 0.0) + w
        adj, loops = nadj, nloops
    remap2: dict[int, int] = {}
    for c in member_of:
        remap2.setdefault(c, len(remap2))
    return [remap2[c] for c in member_of]


# -- clustering ------------------------------------------------------------------------------

def partition(g: CallGraph) -> tuple[list[list[int]], list[int]]:
    """(communities as node-index lists, hub node indices). Not yet merged into misc."""
    n = len(g.nodes)
    hubs = gr.find_hubs(g)
    hub_set = set(hubs)
    und: dict[tuple[int, int], float] = {}
    for (a, b), w in g.directed.items():
        if a in hub_set or b in hub_set:
            continue
        key = (a, b) if a < b else (b, a)
        und[key] = und.get(key, 0.0) + w
    rest = [i for i in range(n) if i not in hub_set]
    pos = {node: p for p, node in enumerate(rest)}
    comm = louvain(len(rest), {(min(pos[a], pos[b]), max(pos[a], pos[b])): w for (a, b), w in und.items()})
    groups: dict[int, list[int]] = {}
    for p, c in enumerate(comm):
        groups.setdefault(c, []).append(rest[p])
    return list(groups.values()), hubs


def _auto_label(cnt: Counter, size: int) -> str:
    if not cnt:
        return "unclassified"
    floor = max(1, size // 10)
    top = [c for c, v in sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0])) if v >= floor][:2]
    return "+".join(top) if top else "unclassified"


# Name-token rules for clusters without feature evidence: label -> lowercase substrings of member
# names. A rule needs at least two named (non-library) members that hit it; the best rule wins.
NAME_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("plugin interface", ("plugin", "initcontrol", "notify", "getinterface")),
    ("rendering", ("render", "paint", "draw", "redraw")),
    ("parsing", ("parse", "token", "lexer", "scan")),
    ("networking", ("socket", "connect", "packet", "protocol")),
    ("file handling", ("loadfile", "savefile", "readfile", "writefile", "openfile", "serializ")),
    ("settings", ("config", "setting", "option", "preference", "profile")),
    ("string utilities", ("string", "strcmp", "trim", "format")),
    ("memory management", ("alloc", "pool", "heap")),
    ("threading", ("thread", "mutex", "lock", "queue")),
)


def name_label(names: list[str]) -> str:
    """Label from the names of the named non-library members (small rule table), or ''."""
    best, best_n = "", 1
    for label, keys in NAME_RULES:
        n = sum(1 for nm in names if any(k in nm.lower() for k in keys))
        if n > best_n:
            best, best_n = label, n
    return best


def runtime_label(fams: list[str]) -> str:
    """``runtime: MFC`` by the majority of the identified families, else plain ``runtime``."""
    cnt = Counter(f for f in fams if f in ("MFC", "CRT", "ATL/STL"))
    if not cnt:
        return RUNTIME_PREFIX
    top = sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return f"{RUNTIME_PREFIX}: {top}"


FID_PREFIX = "FID_conflict:"      # Ghidra Function ID: the function matched a known library routine
STATIC_BINARIES = 3               # a plain name present in at least this many binaries is static runtime
MIXED_SHARE = 0.3                 # share of library members from which an otherwise unlabelled cluster is "mixed"
_FUN_RE = re.compile(r"^(?:FUN|thunk_FUN|SUB|LAB|DAT|PTR|switchD|caseD)_|^FUN_|^<")
_AT_RE = re.compile(r"@\d+$")
_EH_RE = re.compile(r"^(?:Catch|Unwind)(?:_All)?@[0-9a-fA-F]+$")   # MSVC exception funclets


def _norm_name(name: str) -> str:
    """Name without the FID_conflict prefix, the ``@N`` stdcall suffix and surplus leading underscores."""
    n = name[len(FID_PREFIX):] if name.startswith(FID_PREFIX) else name
    n = _AT_RE.sub("", n)
    if n.startswith("___"):
        n = "__" + n.lstrip("_")
    return n


def unnamed(name: str) -> bool:
    return bool(_FUN_RE.match(name))


def runtime_family(name: str, ns: str | None, state: str) -> str | None:
    """Like ``lib_family`` plus the decorations of statically linked code: FID_conflict names (a
    Function ID hit is library code by definition), ``@N`` suffixes, ``___`` prefixes, ``~CClass``."""
    if state == "user":
        return None
    if not ns and "::" in name:                      # qualified name stored without a namespace
        ns, name = name.rsplit("::", 1) if "<" not in name.split("::")[0] else (None, name)
        if not name:
            return None
    fam = lib_family(name, ns, state)
    if fam and fam != "lib":
        return fam
    if _EH_RE.match(name):
        return "CRT"
    n = _norm_name(name)
    if n != name:
        fam2 = lib_family(n, ns, state)
        if fam2 and fam2 != "lib":
            return fam2
    if n.startswith("~") and not ns and n[1:] in MFC_CLASSES:
        return "MFC"
    if name.startswith(FID_PREFIX):
        return "lib"
    return fam


def mixed_label(fams: list[str]) -> str:
    """``mixed: MFC+program``: a cluster with a sizeable library share and program code."""
    top = runtime_label(fams)
    return "mixed: program" if top == RUNTIME_PREFIX else f"mixed: {top.split(': ', 1)[1]}+program"


def _program_evidence(g: CallGraph, own: list[int], exported: set[int]) -> bool:
    """A non-library member that is program-specific: agent-named or an exported entry point."""
    return any(i in exported or g.info[i][1] == "user" for i in own)


def library_nodes(g: CallGraph, exported: set[int] | None = None) -> dict[int, str]:
    """{node: family} for library functions. Three signals, all deterministic:
    1. the name (``runtime_family``) or name_state=library;
    2. a plain name that occurs in at least ``STATIC_BINARIES`` binaries (statically linked runtime
       is the same in every plugin; exports and agent names are excluded);
    3. propagation over the call graph, up to 4 rounds: a function that has callers and only library
       callers joins when it is unnamed (FUN_...), or when it also calls only library functions.
    ``exported`` holds the nodes that are exported entry points: they never join by 2 or 3."""
    exported = exported or set()
    n = len(g.nodes)
    base: dict[int, str] = {}
    for i, (nm, state, ns) in enumerate(g.info):
        fam = runtime_family(nm, ns, state)
        if fam:
            base[i] = fam
    where: dict[str, set[int]] = {}
    for i, (nm, state, ns) in enumerate(g.info):
        if i in base or i in exported or state == "user" or unnamed(nm):
            continue
        where.setdefault(f"{ns}::{nm}" if ns else nm, set()).add(g.nodes[i][0])
    for i, (nm, state, ns) in enumerate(g.info):
        if i not in base and i not in exported and state != "user" and not unnamed(nm)                 and len(where.get(f"{ns}::{nm}" if ns else nm, ())) >= STATIC_BINARIES:
            base[i] = "static"
    callers: dict[int, set[int]] = {}
    callees: dict[int, set[int]] = {}
    for (a, b) in g.directed:
        if a != b:
            callees.setdefault(a, set()).add(b)
            callers.setdefault(b, set()).add(a)
    lib = dict(base)
    for _ in range(4):
        new: dict[int, str] = {}
        for v in range(n):
            if v in lib or v in exported or g.info[v][1] == "user":
                continue
            cs = callers.get(v)
            if not cs or not all(c in lib for c in cs):
                continue
            if unnamed(g.info[v][0]) or all(c in lib for c in callees.get(v, ())):
                new[v] = "prop"
        if not new:
            break
        lib.update(new)
    return lib


def exported_nodes(st: Store, g: CallGraph) -> set[int]:
    """Nodes that are exported entry points of their binary."""
    try:
        rows = st.db.execute("SELECT binary_id, address FROM export").fetchall()
    except Exception:  # noqa: BLE001
        return set()
    ex = {(r[0], r[1]) for r in rows}
    return {i for i, nd in enumerate(g.nodes) if (nd[0], nd[2]) in ex}


def compute(st: Store, bids: list[int], names: dict[int, tuple[str, int]], project: str,
            fingerprint: str) -> ClusterSet:
    g = build_graph(st, bids)
    n = len(g.nodes)
    comms, hubs = partition(g)
    exported = exported_nodes(st, g)
    lib = library_nodes(g, exported)
    callers = [0] * n
    callees = [0] * n
    for (a, b) in g.directed:
        callees[a] += 1
        callers[b] += 1
    big: list[list[int]] = []
    misc: dict[int, list[int]] = {}
    for c in comms:
        if len(c) >= MIN_CLUSTER:
            big.append(sorted(c))
        else:
            for i in c:
                misc.setdefault(g.nodes[i][0], []).append(i)
    big.sort(key=lambda c: (-len(c), c[0]))
    groups: list[tuple[str, str, list[int], int | None]] = []
    for p, c in enumerate(big, 1):
        groups.append((f"C{p}", "c", c, None))
    for p, bid in enumerate(sorted(misc), 1):
        groups.append((f"M{p}", "misc", sorted(misc[bid]), bid))
    if hubs:
        groups.append(("util", "util", hubs, None))
    cid_of: dict[int, str] = {}
    for gid, _k, mem, _b in groups:
        for i in mem:
            cid_of[i] = gid
    internal = [0] * n
    links: dict[str, Counter] = {gid: Counter() for gid, *_ in groups}
    for (a, b), w in g.directed.items():
        ca, cb = cid_of[a], cid_of[b]
        if ca == cb:
            internal[a] += w
            internal[b] += w
        else:
            links[ca][cb] += w
            links[cb][ca] += w
    clusters: list[Cluster] = []
    for gid, kind, mem, bid in groups:
        cnt: Counter = Counter()
        own = [i for i in mem if i not in lib]
        for i in own:
            cnt.update(g.cats.get(i, ()))
        if kind == "util":
            label = ""
        elif kind == "misc":
            label = f"misc {names.get(bid, ('?', 4))[0]}"
        elif len(mem) - len(own) >= RUNTIME_SHARE * len(mem) and not _program_evidence(g, own, exported):
            label = runtime_label([lib[i] for i in mem if i in lib])
        else:
            label = _auto_label(cnt, len(own))
            if label == "unclassified":
                label = name_label([g.info[i][0] for i in own if g.info[i][1] != "auto"]) or label
            if label == "unclassified" and len(mem) - len(own) >= MIXED_SHARE * len(mem):
                label = mixed_label([lib[i] for i in mem if i in lib])
        members = [Member((g.nodes[i][0], g.nodes[i][1], g.nodes[i][2]), g.info[i][0], g.info[i][1],
                          g.info[i][2], g.nodes[i][3], internal[i], callers[i], callees[i]) for i in mem]
        clusters.append(Cluster(gid, kind, label, members,
                                {k: v for k, v in links[gid].items()}, bid))
    return ClusterSet(project, fingerprint, clusters, names, recomputed=True)


# -- persistence -----------------------------------------------------------------------------

def _cache_path(pp: ProjectPaths) -> Path:
    return pp.cache / CACHE_FILE


def _labels_path(pp: ProjectPaths) -> Path:
    return pp.data / LABELS_FILE


def _atomic_write(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, separators=(",", ":")))


def _dump(cs: ClusterSet) -> dict[str, Any]:
    return {"v": ALGO_VERSION, "fp": cs.fingerprint,
            "clusters": [{"id": c.id, "kind": c.kind, "label": c.auto_label, "bin": c.binary,
                          "links": c.links,
                          "m": [[m.key[0], m.key[1], m.key[2], m.centrality, m.callers, m.callees]
                                for m in c.members]} for c in cs.clusters]}


def _load(pp: ProjectPaths, fp: str) -> list[dict[str, Any]] | None:
    try:
        d = json.loads(_cache_path(pp).read_text("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or d.get("v") != ALGO_VERSION or d.get("fp") != fp:
        return None
    return d.get("clusters")


def _fill_names(st: Store, cs: ClusterSet) -> None:
    rows: dict[Key, tuple[int, str, str, str | None]] = {}
    for bid in cs.binaries:
        for r in st.db.execute("SELECT id, space, entry, name, name_state, namespace FROM function "
                               "WHERE binary_id=?", (bid,)):
            rows[(bid, r["space"], r["entry"])] = (r["id"], r["name"], r["name_state"], r["namespace"])
    for c in cs.clusters:
        for m in c.members:
            r = rows.get(m.key)
            if r:
                m.fid, m.name, m.name_state, m.namespace = r


def _fill_features(st: Store, cs: ClusterSet) -> None:
    try:
        rows = st.db.execute("SELECT feature_key, binary_id, space, entry FROM feature_entry").fetchall()
    except Exception:  # noqa: BLE001  no feature tables
        return
    for c in cs.clusters:
        c.features = {}
    for r in rows:
        c = cs.of((r["binary_id"], r["space"], r["entry"]))
        if c is not None:
            c.features[r["feature_key"]] = c.features.get(r["feature_key"], 0) + 1


def _read_labels(pp: ProjectPaths) -> list[dict[str, Any]]:
    try:
        d = json.loads(_labels_path(pp).read_text("utf-8"))
    except (OSError, ValueError):
        return []
    return [x for x in (d.get("labels") if isinstance(d, dict) else []) or []
            if isinstance(x, dict) and x.get("label") and isinstance(x.get("members"), list)]


def _ckey(k: Key) -> str:
    return f"{k[0]}:{k[1]}:{k[2]}"


def match_labels(cs: ClusterSet, labels: list[dict[str, Any]]) -> dict[str, int]:
    """{cluster id: label index} by maximum member overlap (Jaccard >= LABEL_JACCARD), one to one."""
    owner: dict[str, str] = {}
    size: dict[str, int] = {}
    for c in cs.clusters:
        size[c.id] = len(c.members)
        for m in c.members:
            owner[_ckey(m.key)] = c.id
    pairs: list[tuple[float, int, str]] = []
    for li, lab in enumerate(labels):
        keys = set(lab["members"])
        inter: Counter = Counter(owner[k] for k in keys if k in owner)
        for cid, n in inter.items():
            j = n / (len(keys) + size[cid] - n)
            if j >= LABEL_JACCARD:
                pairs.append((j, li, cid))
    pairs.sort(key=lambda p: (-p[0], p[1], p[2]))
    out: dict[str, int] = {}
    used: set[int] = set()
    for _j, li, cid in pairs:
        if cid not in out and li not in used:
            out[cid] = li
            used.add(li)
    return out


def _attach_labels(pp: ProjectPaths, cs: ClusterSet, persist: bool) -> None:
    labels = _read_labels(pp)
    if not labels:
        return
    hit = match_labels(cs, labels)
    changed = False
    for cid, li in hit.items():
        c = cs.get(cid)
        assert c is not None
        c.agent_label = labels[li]["label"]
        keys = [_ckey(m.key) for m in c.members]
        if persist and set(keys) != set(labels[li]["members"]):
            labels[li]["members"] = keys
            changed = True
    if changed:
        _atomic_write(_labels_path(pp), {"labels": labels})


def set_label(pp: ProjectPaths, cs: ClusterSet, cid: str, label: str) -> bool:
    """Store (or with an empty label clear) the agent label of cluster ``cid``."""
    c = cs.get(cid)
    if c is None:
        return False
    labels = _read_labels(pp)
    hit = match_labels(cs, labels)
    li = hit.get(c.id)
    if li is not None:
        labels.pop(li)
    if label:
        labels.append({"label": label, "members": [_ckey(m.key) for m in c.members]})
    _atomic_write(_labels_path(pp), {"labels": labels})
    c.agent_label = label
    return True


# -- public API ------------------------------------------------------------------------------

_runtime_ids = gr.runtime_ids


def fingerprint(st: Store, bins: list[Any]) -> str:
    return gr.fingerprint(st, bins, f"v{ALGO_VERSION}")


def get_clusters(ctx_or_indexer: Any, project: str | None = None) -> ClusterSet:
    """The clusters of the project (cached; recomputed when the fingerprint changes)."""
    ix = getattr(ctx_or_indexer, "indexer", ctx_or_indexer)
    proj = project or ix.resolve_project(None)
    return clusters_for(ix.paths(proj), ix.store(proj), proj)


def clusters_for(pp: ProjectPaths, st: Store, project: str | None = None,
                 runtime: set[int] | None = None) -> ClusterSet:
    """Like get_clusters, from the project paths and store (no indexer)."""
    proj = project or pp.name
    bins = gr.ready_bins(pp, st, runtime)
    names = {b.id: (b.name, b.pointer_size or 4) for b in bins}
    fp = fingerprint(st, bins)
    with _LOCK:
        lock = _LOCKS.setdefault(pp.name, threading.Lock())
    with lock:
        raw = _load(pp, fp)
        if raw is not None:
            cl = [Cluster(c["id"], c["kind"], c["label"],
                          [Member((m[0], m[1], m[2]), centrality=m[3], callers=m[4], callees=m[5])
                           for m in c["m"]], dict(c.get("links") or {}), c.get("bin")) for c in raw]
            cs = ClusterSet(proj, fp, cl, names)
            _fill_names(st, cs)
        else:
            cs = compute(st, [b.id for b in bins], names, proj, fp)
            _fill_names(st, cs)
            try:
                _atomic_write(_cache_path(pp), _dump(cs))
            except OSError:
                pass
        _attach_labels(pp, cs, persist=cs.recomputed)
    _fill_features(st, cs)
    return cs


# -- evidence and rendering ------------------------------------------------------------------

def _preview(value: str, n: int = 40) -> str:
    s = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return '"' + (s[: n - 1] + "…" if len(s) > n else s) + '"'


class Evidence:
    """Per-binary lookups for the ``evidence:`` column of a member line."""

    def __init__(self, st: Store) -> None:
        self.st = st
        self._api: dict[int, dict[int, str]] = {}

    def _names(self, bid: int) -> dict[int, str]:
        m = self._api.get(bid)
        if m is None:
            m = {}
            imp: set[str] = set()
            for r in self.st.db.execute("SELECT name, address FROM import WHERE binary_id=?", (bid,)):
                if r["name"]:
                    imp.add(r["name"])
                    if r["address"] is not None:
                        m[r["address"]] = r["name"]
            for r in self.st.db.execute(
                    "SELECT entry, name FROM function WHERE binary_id=? AND is_thunk=1", (bid,)):
                if r["name"] in imp:
                    m[r["entry"]] = r["name"]
            self._api[bid] = m
        return m

    def of(self, bid: int, fid: int) -> str:
        api = self._names(bid)
        calls: list[str] = []
        strs: list[str] = []
        for r in self.st.db.execute(
                "SELECT dst_addr, kind FROM edge WHERE src_fn=? ORDER BY dst_addr", (fid,)):
            nm = api.get(r["dst_addr"])
            if nm:
                if nm not in calls:
                    calls.append(nm)
            elif r["kind"] not in CALL_KINDS and len(strs) < 2:
                s = self.st.string_at(bid, r["dst_addr"])
                if s is not None and len(s.value) >= 4:
                    p = _preview(s.value)
                    if p not in strs:
                        strs.append(p)
        bits = []
        if calls:
            bits.append("calls " + ", ".join(calls[:3]))
        bits += strs
        return "; ".join(bits)


def _fn_ref(cs: ClusterSet, m: Member) -> str:
    pre = f"{cs.bin_name(m.key[0])}!" if cs.multi else ""
    return f"{pre}{m.qname} {cs.addr(m)}"


def cluster_line(cs: ClusterSet, c: Cluster, link_limit: int = 5, feat_limit: int = 3,
                 key_limit: int = KEY_FUNCTIONS) -> str:
    head = c.id if not c.label else f"{c.id} {c.label}"
    bits = [f"{head}  {c.total} fns ({c.named} named)"]
    keys = c.key_functions(key_limit)
    if keys:
        bits.append("key: " + ", ".join(_fn_ref(cs, m) for m in keys))
    links = sorted(c.links.items(), key=lambda kv: (-kv[1], kv[0]))[:link_limit]
    if links:
        bits.append(", ".join(f"→ {k} {v}" for k, v in links))
    if c.features:
        top = sorted(c.features.items(), key=lambda kv: (-kv[1], kv[0]))[:feat_limit]
        bits.append("features: " + ", ".join(k for k, _ in top))
    return "  ".join(bits)


def ordered(cs: ClusterSet) -> list[Cluster]:
    rank = {"c": 0, "misc": 1, "util": 2}
    return sorted(cs.clusters, key=lambda c: (rank[c.kind], len(c.id), c.id))


def cluster_summary_lines(cs: ClusterSet, limit: int = 8) -> list[str]:
    """Lines for the project map section "Subsystems": top clusters by size, then util/misc."""
    regular = [c for c in ordered(cs) if c.kind == "c" and not c.runtime]
    lines = [cluster_line(cs, c, key_limit=MAP_KEY_FUNCTIONS) for c in regular[:max(0, limit)]]
    if len(regular) > limit:
        lines.append(f"… {len(regular) - limit} more subsystems. function_map() lists them.")
    rt = [c for c in ordered(cs) if c.runtime]
    if rt:
        fams = Counter(c.auto_label.partition(": ")[2] or "other" for c in rt)
        lines.append(f"runtime: {len(rt)} clusters, {sum(c.total for c in rt)} fns ("
                     + ", ".join(f"{k} {v}" for k, v in sorted(fams.items(), key=lambda kv: (-kv[1], kv[0])))
                     + '). function_map(include_runtime=true) lists them.')
    for c in ordered(cs):
        if c.kind != "c":
            lines.append(cluster_line(cs, c, link_limit=3, key_limit=MAP_KEY_FUNCTIONS))
    if lines:
        lines.append('function_map(cluster="C1") lists the functions of a subsystem.')
    return lines
