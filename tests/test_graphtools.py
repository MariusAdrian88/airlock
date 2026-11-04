"""path and graph_export tools, shared graph module, defaults.mermaid, Subsystems map section
(synthetic stores, invented names)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from airlock import projects as P
from airlock.config.catalog import CATALOG
from airlock.config.loader import ConfigError, deep_merge, default_config_text, parse_jsonc, resolve
from airlock.server import clusters as cl
from airlock.server import diagrams as dg
from airlock.server import graph as gr
from airlock.server import linking
from airlock.server import projectmap as pm
from airlock.server import roles
from airlock.server.budget import estimate_tokens
from airlock.server.tools import graphtools as gt
from airlock.server.tools import session as sess
from test_tools import make_ctx

WEIRD = 'we"ird<fn>&x|y#1'


def fn(entry, name, thunk=0, state="auto"):
    return {"entry": entry, "name": name, "name_state": state, "is_thunk": thunk, "size": 0x80,
            "namespace": None}


def call(src, dst, kind="call"):
    return (src + 0x10, dst, kind)


@pytest.fixture
def proj(tmp_path):
    """app.exe: Boot -> Load -> Parse -> Read -> KERNEL32!ReadFile (import node), a longer branch
    Boot -> Menu -> Open -> Parse, Parse -> thunk -> plug.dll!plug_open -> plug_inner -> app!AppLog
    (callback), string "brew.cfg" used by Load, hub util_log (21 callers) with util_target behind it,
    caller_0 with a non-util detour, a feature "file-io" (Read) and one with a weird name."""
    ctx = make_ctx(tmp_path)
    pp = ctx.indexer.paths("proj", create=True)
    st = ctx.indexer.store("proj")
    app = st.upsert_binary("aa" * 32, "app.exe", pointer_size=4, analysis_profile="p1")
    plug = st.upsert_binary("bb" * 32, "plug.dll", pointer_size=4, analysis_profile="p1")
    names = ["Boot", "Load", "Parse", "Read", "Menu", "Open", "AppLog", "util_log", "util_target",
             "alt1", "alt2", WEIRD, "dup_fn"]
    base = {n: 0x1000 + i * 0x100 for i, n in enumerate(names)}
    st.insert_functions(app, [fn(a, n) for n, a in base.items()])
    callers = [0x4000 + i * 0x100 for i in range(21)]
    st.insert_functions(app, [fn(a, f"caller_{i}") for i, a in enumerate(callers)])
    st.insert_functions(app, [fn(0x20000, "PlugOpen", thunk=1)])
    bulk = [0x10000 + i * 0x100 for i in range(200)]
    st.insert_functions(app, [fn(a, f"bulk_{i}") for i, a in enumerate(bulk)])
    b = base
    edges = [call(b["Boot"], b["Load"]), call(b["Load"], b["Parse"]), call(b["Parse"], b["Read"]),
             call(b["Boot"], b["Menu"]), call(b["Menu"], b["Open"]), call(b["Open"], b["Parse"]),
             (b["Read"] + 0x20, 0x30010, "call_ind"),                 # ReadFile import slot
             (b["Parse"] + 0x40, 0x20000, "call"),                    # -> PlugOpen thunk
             (0x20004, 0x30000, "jump"),                              # thunk -> plug.dll slot
             (b["Load"] + 0x30, 0x50000, "read"),                     # string "brew.cfg"
             call(b["util_log"], b["util_target"]),
             call(callers[0], b["alt1"]), call(b["alt1"], b["alt2"]), call(b["alt2"], b["util_target"]),
             call(b["dup_fn"], b["Read"]), call(b["Boot"], b[WEIRD])]
    edges += [call(a, b["util_log"]) for a in callers]
    st.insert_edges(app, edges)
    st.insert_imports(app, [("plug.dll", "PlugOpen", None, 0x30000),
                            ("KERNEL32.DLL", "ReadFile", None, 0x30010)])
    st.insert_exports(app, [("AppLog", 1, b["AppLog"])])
    st.insert_strings(app, [(0x50000, "ascii", "brew.cfg")])
    st.insert_functions(plug, [fn(0x1000, "plug_open"), fn(0x1100, "plug_inner"), fn(0x1200, "dup_fn")])
    st.insert_edges(plug, [call(0x1000, 0x1100), (0x1100 + 0x20, 0x30000, "call_ind")])
    st.insert_imports(plug, [("app.exe", "AppLog", None, 0x30000)])
    st.insert_exports(plug, [("PlugOpen", 1, 0x1000)])
    for x in (app, plug):
        st.link_edges(x)
    st.link_cross_binary(app, [plug])
    st.link_cross_binary(plug, [app])
    with st.db:
        for key, title, ents in (("file-io", "File I/O", [b["Read"]]),
                                 ("odd", "Odd", [b[WEIRD], b["Load"]]),
                                 ("bulk", "Bulk", bulk)):
            st.db.execute("INSERT INTO feature(key, title, source) VALUES (?,?, 'agent')", (key, title))
            st.db.executemany("INSERT INTO feature_entry(feature_key, binary_id, space, entry, reason, source) "
                              "VALUES (?,?, 'ram', ?, 'test', 'agent')", [(key, app, a) for a in ents])
    for x in (app, plug):
        ctx.indexer.set_status(st, x, "ready")
    man = P.read_manifest(pp.manifest)
    man["files"] = [{"path": "app.exe", "group": "core", "sha256": "aa" * 32},
                    {"path": "plug.dll", "group": "own_plugin", "sha256": "bb" * 32}]
    P.write_manifest(pp.manifest, man)
    st.set_meta("link_version", str(linking.LINK_VERSION))     # a current project: no relink on bind
    assert ctx.bind_session("dirty", pp) is None
    return ctx, pp, st, (app, plug), base


def lines(out):
    """Output lines without the budget footer."""
    return [x for x in out.splitlines() if not x.startswith("… ")]


def a(addr):
    return f"0x{addr:08x}"


# -- path -----------------------------------------------------------------------------------

def test_catalog_and_roles(proj):
    ctx, pp, st, _, _ = proj
    for t in ("path", "graph_export"):
        assert t in CATALOG and not CATALOG[t].clean_safe and not CATALOG[t].writes
        assert roles.gate(roles.SessionState(roles.CLEAN, pp), t) is not None


def test_path_within_one_binary(proj):
    ctx, pp, st, _, b = proj
    out = gt.path(ctx, "Boot", "Read", k=1)
    ls = lines(out)
    assert ls[0].startswith("path Boot → Read, 3 hops (1 more paths: cursor=")
    assert ls[1:5] == [f"→ [app.exe] Boot {a(b['Boot'])}",
                       f"→ [app.exe] Load {a(b['Load'])}   call at {a(b['Boot'] + 0x10)}".replace(
                           a(b['Boot'] + 0x10), a(b['Boot'] + 0x10)),
                       f"→ [app.exe] Parse {a(b['Parse'])}   call at {a(b['Load'] + 0x10)}",
                       f"→ [app.exe] Read {a(b['Read'])}   call at {a(b['Parse'] + 0x10)}"]


def test_path_k_and_cursor(proj):
    ctx, pp, st, _, b = proj
    out = gt.path(ctx, "Boot", "Read", k=1)
    cid = re.search(r"cursor=(\S+?)\)", out).group(1)
    nxt = gt.path(ctx, cursor=cid)
    ls = lines(nxt)
    assert ls[0] == "also 4 hops"
    assert [x.split(" ")[2] for x in ls[1:]] == ["Boot", "Menu", "Open", "Parse", "Read"]
    both = gt.path(ctx, "Boot", "Read", k=3)
    assert both.count("also ") == 1 and "more paths" not in both
    assert gt.path(ctx, cursor="c_nope").startswith("error ")


def test_path_across_binaries_via_thunk_and_xedge(proj):
    ctx, pp, st, _, b = proj
    out = gt.path(ctx, "Boot", "plug.dll!plug_inner", k=1)
    ls = lines(out)
    assert "4 hops" in ls[0]
    assert ls[-2].startswith("→ [plug.dll] plug_open 0x00001000   call at " + a(b["Parse"] + 0x40))
    assert ls[-1] == "→ [plug.dll] plug_inner 0x00001100   call at 0x00001010"
    # the plugin calls back into the executable
    back = gt.path(ctx, "plug.dll!plug_inner", "AppLog")
    assert lines(back)[1:] == ["→ [plug.dll] plug_inner 0x00001100",
                               "→ [app.exe] AppLog " + a(b["AppLog"]) + "   call at 0x00001120"]
    assert lines(back)[0] == "path plug.dll!plug_inner → AppLog, 1 hops"


def test_path_to_and_from_import(proj):
    ctx, pp, st, _, b = proj
    for target in ("ReadFile", "KERNEL32!ReadFile", "kernel32!readfile"):
        out = gt.path(ctx, "Boot", target, k=1)
        assert lines(out)[0].startswith("path Boot → ")
        assert "4 hops" in lines(out)[0]
        assert lines(out)[-1] == f"→ import KERNEL32!ReadFile   call at {a(b['Read'] + 0x20)}"
    # an import bound to a project export stands for the exporting function
    out = gt.path(ctx, "PLUG!PlugOpen", "plug_inner")
    assert lines(out)[1:] == ["→ [plug.dll] plug_open 0x00001000",
                              "→ [plug.dll] plug_inner 0x00001100   call at 0x00001010"]
    # an unresolved import has no callees
    out = gt.path(ctx, "ReadFile", "Boot")
    assert out.startswith("error no_path:") and "swap from and to" in out and "8 hops" in out


def test_path_from_string(proj):
    ctx, pp, st, _, b = proj
    out = gt.path(ctx, '"brew.cfg"', "Read")
    assert [x.split(" ")[2] for x in lines(out)[1:]] == ["Load", "Parse", "Read"]
    assert gt.path(ctx, '"*.cfg"', "Read").startswith("path ")                 # glob
    assert gt.path(ctx, '"no such text"', "Read").startswith("error not_found:")


def test_path_from_feature_and_cluster(proj):
    ctx, pp, st, _, b = proj
    out = gt.path(ctx, "Boot", "file-io")
    assert lines(out)[0].startswith("path Boot → file-io, 3 hops") and lines(out)[-1].split(" ")[2] == "Read"
    cs = cl.get_clusters(ctx, "proj")
    cid = cs.of((proj[3][0], "ram", b["Boot"])).id
    out = gt.path(ctx, cid, "ReadFile")
    assert lines(out)[0].startswith(f"path {cid} → ReadFile") and lines(out)[-1].startswith("→ import")
    rid = cs.of((proj[3][0], "ram", b["Read"])).id
    out = gt.path(ctx, "Boot", rid)
    assert lines(out)[0].startswith(f"path Boot → {rid}")


def test_path_util_hub_only_link_is_marked(proj):
    ctx, pp, st, _, b = proj
    g = gr.get_graph(pp, st)
    hubs = gr.find_hubs(g)
    assert [g.info[h][0] for h in hubs] == ["util_log"]
    out = gt.path(ctx, "caller_5", "util_target")
    assert lines(out)[0] == "path caller_5 → util_target, 2 hops [via util]"
    assert "util_log" in out
    # a detour without the hub wins even though it is longer
    out = gt.path(ctx, "caller_0", "util_target")
    assert "via util" not in out and "alt1" in out and "util_log" not in out
    assert lines(out)[0].startswith("path caller_0 → util_target, 3 hops")


def test_path_errors(proj):
    ctx, pp, st, _, b = proj
    out = gt.path(ctx, "AppLog", "Boot")
    assert out.startswith("error no_path:") and "within 8 hops" in out
    out = gt.path(ctx, "Boot", "Read", max_depth=2)
    assert out.startswith("error no_path:") and "within 2 hops" in out and "Raise max_depth to 3" in out
    out = gt.path(ctx, "dup_fn", "Read")
    assert lines(out)[0] == "path dup_fn (2 functions in 2 binaries) → Read, 1 hops"
    assert lines(gt.path(ctx, "app.exe!dup_fn", "Read"))[0].startswith("path app.exe!dup_fn → Read, 1 hops")
    assert gt.path(ctx, "nothing_named_so", "Read").startswith("error not_found:")
    assert gt.path(ctx, "Boot", "plug.dll!nothing").startswith("error not_found:")
    assert gt.path(ctx, "", "Read").startswith("error bad_args:")
    assert gt.path(ctx, "Boot", "0x00dead00").startswith("error not_found:")
    assert gt.path(ctx, "Boot", f"app.exe!{a(b['Read'])}").startswith("path Boot")


def test_path_budget_and_unbound(proj, tmp_path):
    ctx, pp, st, _, b = proj
    tiny = gt.path(ctx, "Boot", "Read", k=3, budget=100)
    assert "cursor=" in tiny.splitlines()[-1] and estimate_tokens(tiny) < 150
    fresh = make_ctx(tmp_path / "other")
    assert gt.path(fresh, "a", "b").startswith("error unbound")


def test_clusters_unchanged_by_graph_refactor(proj):
    ctx, pp, st, (app, plug), b = proj
    cs = cl.get_clusters(ctx, "proj")
    g = gr.get_graph(pp, st)
    # every graph function is in exactly one cluster; thunks are not nodes
    assert sum(c.total for c in cs.clusters) == g.n
    assert not any(g.info[v][0] == "PlugOpen" for v in range(g.n))
    # the call-site addresses are kept per edge
    boot, load = g.index[(app, "ram", b["Boot"])], g.index[(app, "ram", b["Load"])]
    assert g.sites[(boot, load)] == [b["Boot"] + 0x10]
    assert ("KERNEL32", "ReadFile") in g.imports


# -- graph_export ---------------------------------------------------------------------------

def test_export_formats_and_location(proj):
    ctx, pp, st, _, b = proj
    out = gt.graph_export(ctx, "binaries")
    f = pp.dirty / "diagrams" / "binaries.md"
    assert out == f"wrote {f} (mermaid, 2 nodes, 2 edges)" and f.is_file()
    text = f.read_text("utf-8")
    assert text.startswith("```mermaid\nflowchart LR\n") and text.rstrip().endswith("```")
    assert '["app.exe"]' in text and "-->|1|" in text
    out = gt.graph_export(ctx, "binaries", "dot")
    dot = (pp.dirty / "diagrams" / "binaries.dot").read_text("utf-8")
    assert "(dot, 2 nodes, 2 edges)" in out and dot.startswith('digraph "binaries" {') and " -> " in dot
    out = gt.graph_export(ctx, "binaries", "graphml")
    root = ET.fromstring((pp.dirty / "diagrams" / "binaries.graphml").read_text("utf-8"))
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    assert len(root.findall(".//g:node", ns)) == 2 and len(root.findall(".//g:edge", ns)) == 2
    assert "(graphml, 2 nodes, 2 edges)" in out
    assert gt.graph_export(ctx, "binaries", "svg").startswith("error bad_args:")
    assert gt.graph_export(ctx, "nonsense").startswith("error bad_args:")
    assert gt.graph_export(ctx, "cluster:C99").startswith("error not_found:")
    assert gt.graph_export(ctx, "feature:nope").startswith("error not_found:")


def test_export_subsystems_cluster_feature_path(proj):
    ctx, pp, st, (app, plug), b = proj
    cs = cl.get_clusters(ctx, "proj")
    out = gt.graph_export(ctx, "subsystems")
    assert f"{len(cs.clusters)} nodes" in out
    sub = (pp.dirty / "diagrams" / "subsystems.md").read_text("utf-8")
    assert "---" in sub                                           # undirected cluster links
    cid = cs.of((app, "ram", b["Boot"])).id
    out = gt.graph_export(ctx, f"cluster:{cid}")
    assert (pp.dirty / "diagrams" / f"cluster-{cid.lower()}.md").is_file() and "wrote" in out
    out = gt.graph_export(ctx, "feature:file-io", "dot")
    dot = (pp.dirty / "diagrams" / "feature-file-io.dot").read_text("utf-8")
    assert "Read 0x" in dot and "->" in dot
    out = gt.graph_export(ctx, "path:Boot->plug.dll!plug_inner")
    f = pp.dirty / "diagrams" / "path-boot-plug.dll-plug_inner.md"
    assert f.is_file() and "7 nodes" in out
    body = f.read_text("utf-8")
    assert "plug.dll!plug_inner 0x1100" in body and "-->|0x" in body
    assert gt.graph_export(ctx, "path:Boot").startswith("error bad_args:")
    assert gt.graph_export(ctx, "path:AppLog->Boot").startswith("error no_path:")


def test_export_escaping_per_format(proj):
    ctx, pp, st, _, b = proj
    gt.graph_export(ctx, "feature:odd")
    md = (pp.dirty / "diagrams" / "feature-odd.md").read_text("utf-8")
    assert "we#quot;ird#lt;fn#gt;#amp;x#124;y#35;1" in md and '"ird' not in md
    assert md.count("```") == 2
    gt.graph_export(ctx, "feature:odd", "dot")
    dot = (pp.dirty / "diagrams" / "feature-odd.dot").read_text("utf-8")
    assert 'we\\"ird<fn>&x|y#1' in dot
    gt.graph_export(ctx, "feature:odd", "graphml")
    xml = (pp.dirty / "diagrams" / "feature-odd.graphml").read_text("utf-8")
    ET.fromstring(xml)                                            # well-formed
    assert "we\"ird&lt;fn&gt;&amp;x|y#1" in xml


def test_export_cap_summarises_rest(proj):
    ctx, pp, st, _, b = proj
    out = gt.graph_export(ctx, "feature:bulk")
    hid = int(re.search(r"(\d+) more nodes summarised", out).group(1))
    assert "150 nodes" in out and hid >= 51
    md = (pp.dirty / "diagrams" / "feature-bulk.md").read_text("utf-8")
    assert md.count('["') == 150 and f"... {hid} more nodes" in md
    d = dg.Diagram("x", [(f"n{i}", f"l{i}") for i in range(200)], [("n0", "n199", "2"), ("n1", "n180", "3"),
                                                                   ("n0", "n1", "1")])
    c = dg.cap_diagram(d, 150)
    assert len(c.nodes) == 150 and c.nodes[-1][0] == "more" and c.hidden == 51
    assert ("n0", "more", "2") in c.edges and ("n1", "more", "3") in c.edges and ("n0", "n1", "1") in c.edges


def test_export_inline(proj):
    ctx, pp, st, _, b = proj
    out = gt.graph_export(ctx, "binaries", inline=True)
    assert out.splitlines()[0].startswith("wrote ") and "flowchart LR" in out and "```" not in out
    big = gt.graph_export(ctx, "feature:bulk", inline=True, budget=200)
    assert "inline omitted" in big and "flowchart" not in big
    assert "flowchart" not in gt.graph_export(ctx, "binaries")


# -- defaults.mermaid and the map -----------------------------------------------------------

def test_mermaid_flag_writes_three_kinds_of_files(proj):
    ctx, pp, st, _, b = proj
    diag = pp.dirty / "diagrams"
    ctx.refresh_maps("proj")
    assert not diag.exists()                                      # default false
    ctx.config.defaults["mermaid"] = True
    ctx.refresh_maps("proj")
    got = sorted(p.name for p in diag.iterdir())
    assert {"binaries.md", "subsystems.md", "feature-file-io.md", "feature-odd.md",
            "feature-bulk.md"} <= set(got)
    assert "flowchart LR" in (diag / "feature-file-io.md").read_text("utf-8")
    ctx.config.defaults["mermaid"] = False


def test_mermaid_config_validation():
    from airlock.config.keys import DEFAULTS
    base = parse_jsonc(default_config_text())
    assert DEFAULTS["mermaid"] is False
    bad = deep_merge(base, {"mermaid": "yes"})
    with pytest.raises(ConfigError):
        resolve(bad, "dirty", None)


def test_subsystems_section(proj):
    ctx, pp, st, _, b = proj
    dirty = "\n".join(pm.render_dirty(pp, st))
    heads = [ln[3:] for ln in dirty.splitlines() if ln.startswith("## ")]
    assert heads.index("Subsystems") == heads.index("Features") + 1
    sec = dirty.split("## Subsystems")[1].split("\n## ")[0]
    assert "C1 " in sec and "function_map(cluster=\"C1\")" in sec
    clean = "\n".join(pm.render_clean(pp, st))
    assert "Subsystems" not in clean and "C1" not in clean
    pm.write_maps(pp, st)
    assert "## Subsystems" in (pp.dirty / "PROJECT.md").read_text("utf-8")
    assert "Subsystems" not in (pp.clean / "PROJECT.md").read_text("utf-8")


def test_project_open_keeps_first_sections(proj):
    ctx, pp, st, _, b = proj
    text = sess.dirty_open_text(ctx, pp)
    assert "Subsystems" not in text and "## Purpose" in text and "## Features" in text
    assert estimate_tokens(text) <= 1500 + 200                    # map budget plus the session line


# -- endpoint forms: imports, A/W, strings, ambiguous names -------------------------------------

def extend(proj):
    """plug.dll gets: Opener (calls import CreateFileW, CFile::OpenEx), ThunkCaller (calls a thunk
    named like the import ReadFile), an import DeleteFileW nobody calls; app.exe gets CFile::OpenEx."""
    ctx, pp, st, (app, plug), b = proj
    st.insert_functions(plug, [fn(0x1300, "Opener"), fn(0x1400, "ThunkCaller"), fn(0x1500, "ReadFile", thunk=1),
                               dict(fn(0x1600, "OpenEx"), namespace="CFile")])
    st.insert_functions(app, [dict(fn(0x60000, "OpenEx"), namespace="CFile")])
    st.insert_imports(plug, [("KERNEL32.DLL", "CreateFileW", None, 0x30020),
                             ("KERNEL32.DLL", "ReadFile", None, 0x30030),
                             ("KERNEL32.DLL", "DeleteFileW", None, 0x30040)])
    st.insert_edges(plug, [call(0x1300, 0x1600), (0x1300 + 0x20, 0x30020, "call_ind"),
                           call(0x1400, 0x1500), (0x1504, 0x30030, "jump")])
    st.insert_edges(app, [call(b["Boot"], 0x60000)])
    st.link_edges(plug)
    st.link_edges(app)
    return ctx


def head(out):
    return lines(out)[0]


@pytest.mark.parametrize("form", ["ReadFile", "readfile", "KERNEL32!ReadFile", "KERNEL32.DLL!ReadFile",
                                  "kernel32.dll!readfile", "app.exe!ReadFile", "<app.exe>!ReadFile",
                                  "plug.dll!ReadFile", "ReadFileA", "ReadFileW"])
def test_path_import_endpoint_forms(proj, form):
    ctx = extend(proj)
    out = gt.path(ctx, "Boot", form)
    assert head(out).startswith(f"path Boot → {form}"), out
    assert lines(out)[-1].startswith("→ import KERNEL32!ReadFile")


def test_path_import_aw_variant_and_thunk(proj):
    ctx = extend(proj)
    out = gt.path(ctx, "Opener", "CreateFileA")           # only CreateFileW is imported
    assert head(out) == "path Opener → CreateFileA (import KERNEL32!CreateFileW, 1 node), 1 hops"
    assert lines(out)[-1].startswith("→ import KERNEL32!CreateFileW")
    out = gt.path(ctx, "ThunkCaller", "ReadFile")         # call goes through a thunk named like the import
    assert head(out) == "path ThunkCaller → ReadFile, 1 hops"
    assert lines(out)[-1].startswith("→ import KERNEL32!ReadFile")
    out = gt.path(ctx, "Boot", "DeleteFile")
    assert out.startswith("error not_found: import KERNEL32!DeleteFileW exists but no analysed function calls it")
    assert gt.path(ctx, "Boot", "plug.dll!NoSuchApi").startswith("error not_found:")


def test_path_string_fallback_kinds(proj):
    ctx, pp, st, _, b = proj
    for text, how in (('"brew.cfg"', "exact"), ("brew.cfg", "exact"), ("brew", "substring"),
                      ('"rew.c"', "substring"), ("*.cfg", "glob")):
        out = gt.path(ctx, "Boot", text)
        assert head(out) == f"path Boot → {text} (string, {how} match, 1 function), 1 hops", out
        assert lines(out)[-1].startswith("→ [app.exe] Load")
    assert gt.path(ctx, "Boot", "no such text anywhere").startswith("error not_found: no function, import")
    assert gt.path(ctx, "Boot", '"no such text"').startswith("error not_found: no function references")
    assert head(gt.path(ctx, "Boot", "file-io")).startswith("path Boot → file-io, 3 hops")   # feature still wins


def test_path_ambiguous_name_is_multi_target(proj):
    ctx = extend(proj)
    out = gt.path(ctx, "Boot", "CFile::OpenEx")
    assert head(out) == "path Boot → CFile::OpenEx (2 functions in 2 binaries), 1 hops", out
    assert lines(out)[-1].startswith("→ [app.exe] CFile::OpenEx")
    out = gt.path(ctx, "CFile::OpenEx", "Boot")
    assert head(out).startswith("error no_path:")                       # not an error about ambiguity
    out = gt.path(ctx, "Opener", "CFile::OpenEx")
    assert "(2 functions in 2 binaries)" in head(out) and "[plug.dll] CFile::OpenEx" in out
    assert gt.path(ctx, "Boot", "app.exe!CFile::OpenEx").startswith("path Boot → app.exe!CFile::OpenEx, 1 hops")


def test_graph_export_path_with_ambiguous_names(proj):
    ctx = extend(proj)
    pp = proj[1]
    out = gt.graph_export(ctx, "path:Boot->CFile::OpenEx")
    assert out.startswith("wrote ") and "2 nodes" in out
    out = gt.graph_export(ctx, "path:dup_fn->Read")
    assert out.startswith("wrote ") and "ambiguous" not in out
    assert gt.graph_export(ctx, "path:Boot->nothing_like_this_zz").startswith("error not_found:")
