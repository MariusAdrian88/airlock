"""Subsystem clusters and the function_map / cluster_label tools (synthetic stores, invented names)."""

from __future__ import annotations

import json
import random
import time

import pytest

from airlock import projects as P
from airlock.config.catalog import CATALOG
from airlock.index.store import Store
from airlock.server import clusters as cl
from airlock.server import roles
from airlock.server.tools import fmap
from test_tools import make_ctx


def fn(entry, name, state="auto", thunk=0, ns=None):
    return {"entry": entry, "name": name, "name_state": state, "is_thunk": thunk, "size": 0x80,
            "namespace": ns}


def community(st, bid, base, n, prefix, state="auto"):
    """n functions at base+i*0x100, calling each other pairwise (complete graph)."""
    st.insert_functions(bid, [fn(base + i * 0x100, f"{prefix}{i}", state) for i in range(n)])
    edges = [(base + i * 0x100 + 4 + 4 * j, base + j * 0x100, "call")
             for i in range(n) for j in range(n) if i < j]
    st.insert_edges(bid, edges)


def e(base, i):
    return base + i * 0x100


@pytest.fixture
def proj(tmp_path):
    """app.exe: communities A (0x1000, 8 fns) and B (0x9000, 8 fns) joined by one edge, plus
    a lib.dll community exporting LibFn that app reaches through a thunk, and a runtime dll."""
    ctx = make_ctx(tmp_path)
    pp = ctx.indexer.paths("proj", create=True)
    st = ctx.indexer.store("proj")
    app = st.upsert_binary("aa" * 32, "app.exe", pointer_size=4, analysis_profile="p1")
    lib = st.upsert_binary("bb" * 32, "lib.dll", pointer_size=4, analysis_profile="p1")
    rt = st.upsert_binary("cc" * 32, "crt_rt.dll", pointer_size=4, analysis_profile="p1")
    community(st, app, 0x1000, 8, "alpha", "user")
    community(st, app, 0x9000, 8, "beta")
    st.insert_edges(app, [(e(0x1000, 0) + 0x80 - 4, e(0x9000, 0), "call")])      # the single bridge
    # app -> thunk LibFn -> slot; slot bound to lib.dll!LibFn (cross-binary)
    st.insert_functions(app, [fn(0x20000, "LibFn", "library", thunk=1), fn(0x21000, "gamma")])
    st.insert_imports(app, [("lib.dll", "LibFn", None, 0x30000), ("KERNEL32.DLL", "ReadFile", None, 0x30010)])
    st.insert_edges(app, [(0x20004, 0x30000, "jump"),
                          (e(0x1000, 1) + 0x70, 0x20000, "call"),        # alpha1 -> LibFn thunk
                          (e(0x1000, 2) + 0x70, 0x30010, "call_ind"),    # alpha2 -> ReadFile slot
                          (e(0x1000, 3) + 0x70, 0x30000, "call_ind")])   # alpha3 -> lib slot direct
    community(st, lib, 0x1000, 6, "libfn")
    st.insert_exports(lib, [("LibFn", 1, 0x1000)])
    community(st, rt, 0x1000, 5, "rtfn")
    for b in (app, lib, rt):
        st.link_edges(b)
    st.link_cross_binary(app, [lib, rt])
    for b in (app, lib, rt):
        ctx.indexer.set_status(st, b, "ready")
    man = P.read_manifest(pp.manifest)
    man["files"] = [{"path": "app.exe", "group": "core", "sha256": "aa" * 32},
                    {"path": "lib.dll", "group": "own_plugin", "sha256": "bb" * 32},
                    {"path": "crt_rt.dll", "group": "runtime", "sha256": "cc" * 32}]
    P.write_manifest(pp.manifest, man)
    return ctx, pp, st, (app, lib, rt)


def fresh(pp):
    """Drop the cache so the next call recomputes."""
    (pp.cache / cl.CACHE_FILE).unlink(missing_ok=True)


def keys_of(cs):
    return {c.id: sorted(m.key for m in c.members) for c in cs.clusters}


def test_catalog_flags():
    for name in ("function_map", "cluster_label"):
        assert name in CATALOG and not CATALOG[name].clean_safe and not CATALOG[name].writes


def test_two_communities_joined_by_one_edge(proj):
    ctx, pp, st, (app, lib, rt) = proj
    cs = cl.get_clusters(ctx, "proj")
    alpha = cs.of((app, "ram", 0x1000))
    beta = cs.of((app, "ram", 0x9000))
    assert alpha is not None and beta is not None and alpha.id != beta.id
    assert {m.name for m in alpha.members if m.key[0] == app} >= {f"alpha{i}" for i in range(8)}
    assert {m.name for m in beta.members} == {f"beta{i}" for i in range(8)}
    assert beta.links.get(alpha.id) == 1 and alpha.links.get(beta.id) == 1
    assert alpha.named == 8 and beta.named == 0


def test_thunk_collapse_across_binaries_and_runtime_excluded(proj):
    ctx, pp, st, (app, lib, rt) = proj
    cs = cl.get_clusters(ctx, "proj")
    libc = cs.of((lib, "ram", 0x1000))
    alpha = cs.of((app, "ram", 0x1000))
    assert libc is not None
    # alpha1 -> thunk, alpha3 -> slot directly: two edges reach lib.dll!LibFn, in a lib cluster
    assert libc.links.get(alpha.id, 0) == 2 and alpha.links.get(libc.id, 0) == 2
    # no thunk or runtime member anywhere
    names = {m.name for c in cs.clusters for m in c.members}
    assert "LibFn" not in {m.name for c in cs.clusters for m in c.members if m.key[0] == app}
    assert not any(n.startswith("rtfn") for n in names)
    assert all(m.key[0] != rt for c in cs.clusters for m in c.members)
    assert rt not in cs.binaries


def test_unknown_group_is_included(proj):
    ctx, pp, st, (app, lib, rt) = proj
    man = P.read_manifest(pp.manifest)
    man["files"] = []
    P.write_manifest(pp.manifest, man)
    cs = cl.get_clusters(ctx, "proj")
    assert rt in cs.binaries and cs.of((rt, "ram", 0x1000)) is not None


def test_hub_goes_to_util(tmp_path):
    ctx = make_ctx(tmp_path)
    st = ctx.indexer.store("proj")
    b = st.upsert_binary("aa" * 32, "app.exe", pointer_size=4)
    community(st, b, 0x1000, 10, "left")
    community(st, b, 0x9000, 10, "right")
    st.insert_functions(b, [fn(0x50000, "hubfn")])
    st.insert_edges(b, [(e(0x1000, i) + 0x60, 0x50000, "call") for i in range(10)]
                    + [(e(0x9000, i) + 0x60, 0x50000, "call") for i in range(10)]
                    + [(e(0x1000, 0) + 0x70, 0x50000, "call_ind")])
    st.link_edges(b)
    ctx.indexer.set_status(st, b, "ready")
    cs = cl.get_clusters(ctx, "proj")
    util = cs.get("util")
    assert util is not None and [m.name for m in util.members] == ["hubfn"]
    assert cs.of((b, "ram", 0x1000)).id != cs.of((b, "ram", 0x9000)).id     # hub did not glue them
    assert util.links  # but its links are still reported


def test_small_clusters_merge_into_misc(proj):
    ctx, pp, st, (app, lib, rt) = proj
    cs = cl.get_clusters(ctx, "proj")
    g = cs.of((app, "ram", 0x21000))                  # gamma: no edges at all
    assert g is not None and g.kind == "misc" and g.binary == app and "misc app.exe" in g.label


def test_deterministic(proj):
    ctx, pp, st, _ = proj
    a = cl.get_clusters(ctx, "proj")
    fresh(pp)
    b = cl.get_clusters(ctx, "proj")
    assert b.recomputed and keys_of(a) == keys_of(b)
    assert [c.id for c in a.clusters] == [c.id for c in b.clusters]
    sizes = [c.total for c in b.clusters if c.kind == "c"]
    assert sizes == sorted(sizes, reverse=True)


def test_cache_and_fingerprint_invalidation(proj):
    ctx, pp, st, (app, lib, rt) = proj
    first = cl.get_clusters(ctx, "proj")
    assert first.recomputed and (pp.cache / cl.CACHE_FILE).exists()
    again = cl.get_clusters(ctx, "proj")
    assert not again.recomputed and keys_of(again) == keys_of(first)
    assert [m.name for m in again.clusters[0].members] == [m.name for m in first.clusters[0].members]
    st.insert_edges(app, [(e(0x9000, 1) + 0x70, e(0x9000, 2), "call")])
    st.link_edges(app)
    third = cl.get_clusters(ctx, "proj")
    assert third.recomputed and third.fingerprint != first.fingerprint
    st.db.execute("UPDATE binary SET analysis_profile='p2' WHERE id=?", (app,))
    st.db.commit()
    assert cl.get_clusters(ctx, "proj").fingerprint != third.fingerprint


def test_label_survives_recomputation(proj):
    ctx, pp, st, (app, lib, rt) = proj
    assert ctx.bind_session("dirty", pp) is None
    out = fmap.cluster_label(ctx, "C1", "Alpha  engine")
    assert out.startswith('C1 labeled "Alpha engine"')
    cs = cl.get_clusters(ctx, "proj")
    c1 = cs.get("C1")
    assert c1.label == "Alpha engine"
    members = {m.key for m in c1.members}
    # grow the cluster by two functions: overlap stays well above 0.5, fingerprint changes
    st.insert_functions(app, [fn(0x60000, "extra0"), fn(0x60100, "extra1")])
    st.insert_edges(app, [(0x60004, e(0x1000, 4), "call"), (0x60104, e(0x1000, 5), "call"),
                          (0x60008, 0x60100, "call")])
    st.link_edges(app)
    cs2 = cl.get_clusters(ctx, "proj")
    assert cs2.recomputed
    owner = cs2.of(next(iter(members)))
    assert owner.agent_label == "Alpha engine" and owner.label == "Alpha engine"
    assert sum(1 for c in cs2.clusters if c.agent_label) == 1
    # a different partition (no overlap) must not inherit it
    assert cl.match_labels(cs2, [{"label": "x", "members": ["9:ram:1", "9:ram:2"]}]) == {}
    # clear
    assert "cleared" in fmap.cluster_label(ctx, owner.id, "")
    assert cl.get_clusters(ctx, "proj").get(owner.id).agent_label == ""
    assert fmap.cluster_label(ctx, "C99", "x").startswith("error not_found")
    assert fmap.cluster_label(ctx, "C1", "x" * 80).startswith("error too_long")


def test_auto_label_from_imports(proj):
    ctx, pp, st, (app, lib, rt) = proj
    cs = cl.get_clusters(ctx, "proj")
    c = cs.of((app, "ram", 0x1000))
    if cl._fx is not None:
        assert "file-io" in c.auto_label
    assert cs.of((app, "ram", 0x9000)).auto_label == "unclassified"


def test_local_category_fallback(monkeypatch):
    monkeypatch.setattr(cl, "_fx", None)
    assert cl.api_category("__imp_ReadFile") == "file-io"
    assert cl.api_category("RegOpenKeyExA") == "config"
    assert cl.api_category("nothing_here") is None


def test_function_map_listing(proj):
    ctx, pp, st, (app, lib, rt) = proj
    assert fmap.function_map(ctx).startswith("error unbound")
    assert ctx.bind_session("dirty", pp) is None
    out = fmap.function_map(ctx)
    lines = out.splitlines()
    assert lines[0].startswith("C1 ") and "fns (" in lines[0] and "named)" in lines[0]
    assert any("key: " in ln and "app.exe!alpha" in ln for ln in lines)   # multi-binary: bin! prefix
    assert any("→ C" in ln for ln in lines)
    assert lines[-1].startswith("M") or lines[-1].startswith("C") or lines[-1].startswith("util")
    assert "libfn" in out and "0x00001000" in out


def test_function_map_cluster_members_and_evidence(proj):
    ctx, pp, st, (app, lib, rt) = proj
    assert ctx.bind_session("dirty", pp) is None
    cs = cl.get_clusters(ctx, "proj")
    cid = cs.of((app, "ram", 0x1000)).id
    out = fmap.function_map(ctx, cluster=cid.lower())
    lines = out.splitlines()
    assert lines[0].startswith(f"{cid} ") and "fns (" in lines[0]
    assert all(ln.startswith("[") for ln in lines[1:] if not ln.startswith("…"))
    a2 = next(ln for ln in lines if " alpha2 " in ln)
    assert "callers " in a2 and "callees " in a2 and "evidence: calls ReadFile" in a2
    assert fmap.function_map(ctx, cluster="C99").startswith("error not_found")
    # binary scope filters members
    only_lib = fmap.function_map(ctx, scope="lib.dll", cluster=cid)
    assert "alpha" not in only_lib or "[lib.dll]" in only_lib


def test_function_map_scopes(proj):
    ctx, pp, st, (app, lib, rt) = proj
    assert ctx.bind_session("dirty", pp) is None
    cs = cl.get_clusters(ctx, "proj")
    alpha = cs.of((app, "ram", 0x1000))
    beta = cs.of((app, "ram", 0x9000))
    by_bin = fmap.function_map(ctx, scope="lib.dll")
    assert "libfn" in by_bin and "beta0" not in by_bin
    out = fmap.function_map(ctx, scope="app.exe!beta0")
    assert out.splitlines()[0].startswith("beta0 (0x00009000) is in ")
    assert f"is in {beta.id}" in out.splitlines()[0] and f"neighbours: {alpha.id} " in out.splitlines()[0]
    assert {ln.split()[0] for ln in out.splitlines()[1:]} == {alpha.id, beta.id}
    assert fmap.function_map(ctx, scope="app.exe!LibFn").startswith("error not_clustered")
    assert fmap.function_map(ctx, scope="nosuchthing").startswith("error")
    # feature scope
    st.define_feature("cfg", "Config", "", "now")
    st.add_feature_entries("cfg", app, [("ram", e(0x9000, 0), "agent: Config")])
    feat = fmap.function_map(ctx, scope="cfg")
    assert feat.splitlines()[0].startswith(beta.id + " ") and "features: cfg" in feat
    assert len(feat.splitlines()) == 1


def test_function_map_budget_and_cursor(proj):
    ctx, pp, st, _ = proj
    assert ctx.bind_session("dirty", pp) is None
    full = fmap.function_map(ctx, limit=100, budget=2000)
    n = len(full.splitlines())
    page = fmap.function_map(ctx, limit=1)
    assert "more lines. cursor=c_" in page.splitlines()[-1]
    cid = page.splitlines()[-1].rsplit("cursor=", 1)[1]
    rest = fmap.function_map(ctx, cursor=cid, budget=2000)
    assert fmap.function_map(ctx, cursor="c_zzzz").startswith("error bad_cursor")
    assert len(page.splitlines()) - 1 + len(rest.splitlines()) == n
    tiny = fmap.function_map(ctx, cluster="C1", limit=2)
    assert "cursor=" in tiny.splitlines()[-1] and len(tiny.splitlines()) == 4


def test_role_gate(proj):
    ctx, pp, st, _ = proj
    clean = roles.SessionState(roles.CLEAN, pp)
    for t in ("function_map", "cluster_label"):
        assert roles.gate(clean, t) is not None


def test_summary_lines(proj):
    ctx, pp, st, _ = proj
    cs = cl.get_clusters(ctx, "proj")
    lines = cl.cluster_summary_lines(cs, 2)
    assert lines[0].startswith("C1 ") and any("more subsystems" in ln for ln in lines) or len(
        [c for c in cs.clusters if c.kind == "c"]) <= 2
    assert lines[-1].startswith("function_map(")
    assert cl.cluster_summary_lines(cl.ClusterSet("x", "f", [], {}), 5) == []


def test_performance_20k_functions_200k_edges(tmp_path, capsys):
    """Planted-community random graph; the whole compute (SQL read, collapse, Louvain) stays < 10 s."""
    rng = random.Random(7)
    st = Store(tmp_path / "big.sqlite")
    b = st.upsert_binary("dd" * 32, "big.exe", pointer_size=4)
    n, ncomm, m = 20000, 100, 200000
    st.insert_functions(b, [fn(0x1000 + i * 0x40, f"f{i}") for i in range(n)])
    ids = [r[0] for r in st.db.execute("SELECT id FROM function WHERE binary_id=? ORDER BY entry", (b,))]
    per = n // ncomm
    rows = []
    for k in range(m):
        i = rng.randrange(n)
        if rng.random() < 0.9:
            j = (i // per) * per + rng.randrange(per)
        else:
            j = rng.randrange(n)
        if i == j:
            continue
        rows.append((b, ids[i], 0x1000 + i * 0x40 + 4 + (k % 16) * 2, ids[j], 0x1000 + j * 0x40, "call"))
    with st.db:
        st.db.executemany("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) "
                          "VALUES (?,?,?,?,?,?)", rows)
    t0 = time.perf_counter()
    cs = cl.compute(st, [b], {b: ("big.exe", 4)}, "big", "fp")
    dt = time.perf_counter() - t0
    regular = [c for c in cs.clusters if c.kind == "c"]
    with capsys.disabled():
        print(f"\n[clusters] {n} functions / {len(rows)} edges -> {len(regular)} clusters, "
              f"{sum(1 for c in cs.clusters if c.kind == 'util' for _ in c.members)} util, "
              f"{dt:.2f} s")
    assert dt < 10
    assert 50 <= len(regular) <= 400
    st.close()
