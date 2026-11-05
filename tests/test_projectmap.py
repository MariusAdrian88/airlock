"""Project map, map tools, project_open output, PROJECT.md regeneration (synthetic rows)."""

from __future__ import annotations

import json

import pytest

from airlock import projects as P
from airlock.config.catalog import CATALOG
from airlock.server import features as fx
from airlock.server import projectmap as pm
from airlock.server import roles
from airlock.server.budget import estimate_tokens
from airlock.server.tools import map as mt
from airlock.server.tools import session as sess
from test_features import build
from test_tools import make_ctx

PURPOSE = "Edits brew logs and exports reports."


@pytest.fixture
def proj(tmp_path):
    ctx = make_ctx(tmp_path)
    pp = ctx.indexer.paths("proj", create=True)
    st = ctx.indexer.store("proj")
    app, lib, rt = build(st)
    for b in (app, lib, rt):
        ctx.indexer.set_status(st, b, "ready")
    files = [
        {"path": "app.exe", "group": "core", "kind": "pe", "sha256": "aa" * 32, "state": "ready",
         "code_size": 3 << 20},
        {"path": "plug/lib.dll", "group": "own_plugin", "kind": "pe", "sha256": "bb" * 32,
         "state": "ready", "code_size": 1 << 20},
        {"path": "msvcrt_rt.dll", "group": "runtime", "kind": "pe", "sha256": "cc" * 32,
         "state": "ready", "code_size": 1 << 19},
        {"path": "sample.blg", "group": "data", "kind": "data", "state": "ready"},
    ]
    man = P.read_manifest(pp.manifest)
    man.update({"source": {"path": str(tmp_path / "srcprog"), "root_exe": "app.exe"},
                "selected_option": "B", "files": files})
    P.write_manifest(pp.manifest, man)
    fx.derive_project(pp, st)
    return ctx, pp, st, (app, lib, rt)


def test_dirty_map_sections_and_identifiers(proj):
    ctx, pp, st, (app, lib, rt) = proj
    pm.set_purpose(st, PURPOSE)
    text = "\n".join(pm.render_dirty(pp, st))
    heads = [ln for ln in text.splitlines() if ln.startswith("## ")]
    assert heads == [f"## {s}" for s in pm.SECTIONS]
    assert PURPOSE in text and "root app.exe" in text and "option B" in text
    # binaries: name, group, state, code, named/total, role
    assert "app.exe | core | ready | code 3.0 MB | functions 3/12 named" in text
    assert "main program" in text
    assert "lib.dll | own_plugin | ready" in text and "plugin: exports LibRead; used by app.exe" in text
    assert "msvcrt_rt.dll | runtime | ready" in text and "runtime library" in text
    # relations: who imports whom with counts
    assert "app.exe -> lib.dll: " in text and " imports" in text
    # features with coverage and the drill-in call; data-format from the manifest extension
    assert 'file-io | File input/output |' in text and 'feature(key="file-io")' in text
    assert "named 0 of " in text and "seeds " in text and 'feature(key="data-format:blg")' in text
    # knowledge with zero counts, frontier with address and the next call, where to write
    assert "notes 0 | specs 0 | published specs 0" in text
    front = text.split("## Frontier")[1].split("## Where to write")[0]
    assert "FUN_a (0x00401100) in app.exe" in front and "caller" in front
    assert "function(binary=app.exe, target=0x00401100)" in front
    assert "FUN_a (0x00401100) in app.exe | 1 caller | calls ReadFile" in front
    assert "FUN_rt" not in front                       # runtime library excluded
    assert str(pp.dirty / "work") in text.split("## Where to write")[1]
    assert "project_describe" in text.split("## Where to write")[1]


def test_frontier_ranks_by_callers_and_skips_named(proj):
    ctx, pp, st, _ = proj
    with st.db:
        st.db.execute("UPDATE function SET name='parse_log', name_state='user' WHERE name='FUN_a'")
    rows = pm.frontier_rows(st, runtime_ids={proj[3][2]})
    names = [r["name"] for r in rows]
    assert "FUN_a" not in names and "FUN_b" in names and len(rows) <= pm.FRONTIER_TOP
    assert "recently named: parse_log (0x00401100) in app.exe" in "\n".join(pm.knowledge_lines(pp, st))


def test_clean_map_has_no_code_names(proj):
    ctx, pp, st, _ = proj
    pm.set_purpose(st, "Edits brew logs with app.exe, see lib.dll near 0x00401100.")
    (pp.specs).mkdir(parents=True, exist_ok=True)
    (pp.specs / "specs.json").write_text(json.dumps({"specs": [
        {"topic": "file-format/blg", "title": "Log container", "version": "2", "status": "stable"}]}))
    text = "\n".join(pm.render_clean(pp, st))
    assert "# proj (clean map)" in text and "Edits brew logs with" in text
    assert "file-format/blg | Log container | v2 | stable" in text
    for leak in ("app.exe", "lib.dll", "msvcrt", "0x00401100", "FUN_", "WinMain", str(pp.dirty)):
        assert leak not in text
    assert "## Binaries" not in text and "## Frontier" not in text


def test_write_maps_files(proj):
    ctx, pp, st, _ = proj
    pm.set_purpose(st, PURPOSE)
    pm.write_maps(pp, st)
    d = (pp.dirty / "PROJECT.md").read_text("utf-8")
    c = (pp.clean / "PROJECT.md").read_text("utf-8")
    assert "## Frontier" in d and "app.exe" in d
    assert PURPOSE in c and "app.exe" not in c and "0x" not in c


def test_hook_regenerates_project_md_after_ready(proj):
    ctx, pp, st, (app, lib, rt) = proj
    assert ctx._on_ready in ctx.indexer.ready_hooks
    assert not (pp.dirty / "PROJECT.md").exists()
    ctx.indexer.ready_hooks[0]("proj", app)
    assert ctx.wait_maps(20)
    first = (pp.dirty / "PROJECT.md").read_text("utf-8")
    assert "named 0 of " in first and (pp.clean / "PROJECT.md").exists()
    with st.db:
        st.db.execute("UPDATE function SET name='read_it', name_state='user' WHERE name='FUN_a'")
    ctx.indexer.ready_hooks[0]("proj", lib)
    assert ctx.wait_maps(20)
    second = (pp.dirty / "PROJECT.md").read_text("utf-8")
    assert second != first and "read_it (0x00401100)" in second


# -- tools ------------------------------------------------------------------------------------------

def bound(proj):
    ctx, pp, st, _ = proj
    assert ctx.bind_session("dirty", pp) is None
    assert ctx.wait_maps(20)                    # bind may start a background map refresh: let it finish
    return ctx, pp, st


def test_overview_returns_map_and_pages(proj):
    ctx, pp, st = bound(proj)
    out = mt.overview(ctx)
    assert out.startswith("## Purpose") and "## Where to write" in out
    small = mt.overview(ctx, budget=120)
    assert "more lines. cursor=" in small
    cid = small.rsplit("cursor=", 1)[1].strip()
    rest = mt.overview(ctx, cursor=cid)
    assert rest and "error" not in rest.splitlines()[0]
    assert mt.overview(ctx, cursor="c_zzzz").startswith("error bad_cursor")


def test_project_describe(proj):
    ctx, pp, st = bound(proj)
    assert mt.project_describe(ctx, "  ").startswith("error empty_purpose")
    assert mt.project_describe(ctx, "x" * 2000).startswith("error too_long")
    out = mt.project_describe(ctx, PURPOSE)
    assert out.startswith("purpose set") and PURPOSE in mt.overview(ctx)
    assert PURPOSE in (pp.dirty / "PROJECT.md").read_text("utf-8")
    assert PURPOSE in (pp.clean / "PROJECT.md").read_text("utf-8")


def test_features_and_feature_tools(proj):
    ctx, pp, st = bound(proj)
    out = mt.features(ctx)
    assert "file-io | File input/output | " in out and 'feature(key="config")' in out
    f = mt.feature(ctx, "file-io", depth=2)
    lines = f.splitlines()
    assert lines[0].startswith("feature file-io: File input/output |")
    assert "app.exe | FUN_a (0x00401100) | auto | calls ReadFile" in f
    assert "app.exe | FUN_b (0x00401200) | auto | caller of FUN_a" in f
    assert "lib.dll | FUN_lr (0x00001000) | auto | calls ReadFile" in f
    assert "FUN_d" not in f and "msvcrt" not in f
    assert mt.feature(ctx, "nope").startswith("error not_found: no feature 'nope' (have: ")
    assert mt.feature(ctx, "").startswith("error not_found")


def test_feature_limit_and_cursor(proj):
    ctx, pp, st = bound(proj)
    full = mt.feature(ctx, "file-io", depth=2, limit=100)
    n_entries = sum(1 for ln in full.splitlines() if " | auto | " in ln)
    assert n_entries >= 5
    page = mt.feature(ctx, "file-io", depth=2, limit=2)
    assert sum(1 for ln in page.splitlines() if " | auto | " in ln) == 2
    assert f"… {n_entries - 2} more lines. cursor=" in page
    cid = page.rsplit("cursor=", 1)[1].strip()
    rest = mt.feature(ctx, "file-io", cursor=cid)
    assert sum(1 for ln in rest.splitlines() if " | auto | " in ln) == n_entries - 2
    assert mt.feature(ctx, "config", cursor=cid).startswith("error bad_cursor")


def test_feature_define_and_survival(proj):
    ctx, pp, st = bound(proj)
    assert mt.feature_define(ctx, "Bad Key", "t").startswith("error bad_key")
    assert mt.feature_define(ctx, "open-project-file").startswith("error need_title")
    assert mt.feature_define(ctx, "open-project-file", "Open a project file",
                             functions="app.exe!WinMain, FUN_filter").startswith(
        "feature open-project-file defined: Open a project file | 2 functions added, 2 entry points")
    assert mt.feature_define(ctx, "x1", "t", functions="no_such_fn").startswith("error not_found")
    assert mt.feature_define(ctx, "x1", "t", functions="FUN_zz").startswith("error")
    out = mt.feature(ctx, "open-project-file")
    assert "app.exe | WinMain (0x00401000) | user | agent: Open a project file" in out
    assert "[agent]" in mt.features(ctx)
    mt.features(ctx, refresh=True)                      # re-derive: the agent feature stays
    assert "WinMain (0x00401000)" in mt.feature(ctx, "open-project-file")
    assert 'open-project-file [agent] | Open a project file | seeds 2, total 2' in mt.overview(ctx)
    # refine: add one more function, keep the title
    assert "updated" in mt.feature_define(ctx, "open-project-file", "", functions="FUN_cfg", topics="io")
    assert "3 entry points" in mt.feature_define(ctx, "open-project-file", "", functions="FUN_cfg")


def test_ambiguous_function_across_binaries(proj):
    ctx, pp, st = bound(proj)
    app = proj[3][0]
    st.insert_functions(app, [{"entry": 0x430000, "name": "Impl", "name_state": "auto", "size": 8}])
    out = mt.feature_define(ctx, "dup", "Dup", functions="Impl")
    assert out.startswith("error ambiguous:") and "app.exe!Impl" in out and "lib.dll!Impl" in out
    assert mt.feature_define(ctx, "dup", "Dup", functions="lib.dll!Impl").startswith("feature dup defined")


# -- project_open ----------------------------------------------------------------------------------

def test_project_open_dirty_returns_first_sections(proj):
    ctx, pp, st, _ = proj
    pm.set_purpose(st, PURPOSE)
    out = sess.project_open(ctx, "proj", "dirty")
    lines = out.splitlines()
    assert lines[0].startswith("session dirty for proj: write notes and scratch files only under")
    assert lines[1].startswith("binaries: ")
    assert [ln for ln in lines if ln.startswith("## ")] == ["## Purpose", "## Binaries", "## Features"]
    assert PURPOSE in out and "app.exe | core | ready" in out and 'feature(key="file-io")' in out
    assert "## Relations" not in out and "More: overview()" in lines[-1]
    assert estimate_tokens(out) <= 1500 + 100
    assert ctx.session.role == "dirty" and (pp.dirty / "PROJECT.md").exists()


def test_project_open_dirty_stays_within_budget_with_many_features(proj):
    ctx, pp, st, (app, _l, _r) = proj
    for i in range(80):
        st.define_feature(f"feat-{i}", f"A feature number {i} with a long descriptive title", "", "t")
        st.add_feature_entries(f"feat-{i}", app, [("ram", 0x401000, "agent: x")])
    out = sess.project_open(ctx, "proj", "dirty")
    assert estimate_tokens(out) <= 1500 + 100 and "more lines. cursor=" in out


def test_project_open_clean_returns_clean_map(proj):
    ctx, pp, st, _ = proj
    pm.set_purpose(st, "Edits brew logs for app.exe.")
    out = sess.project_open(ctx, "proj", "clean")
    assert out.splitlines()[0].startswith("session clean for proj:")
    assert "# proj (clean map)" in out and "Edits brew logs for" in out
    for leak in ("app.exe", "lib.dll", "FUN_", "0x00", "## Binaries"):
        assert leak not in "\n".join(out.splitlines()[1:])


def test_map_tools_are_dirty_only(proj):
    ctx, pp, st, _ = proj
    clean = roles.SessionState(roles.CLEAN, pp)
    for t in ("overview", "project_describe", "features", "feature", "feature_define"):
        assert not CATALOG[t].clean_safe and not CATALOG[t].writes
        assert roles.gate(clean, t).startswith("error wrong_role:")
        assert roles.gate(roles.SessionState(), t).startswith("error unbound:")
        assert roles.gate(roles.SessionState(roles.DIRTY, pp), t) is None


def test_bind_session_resumes_project(proj, monkeypatch):
    ctx, pp, st, _ = proj
    seen = []
    monkeypatch.setattr(ctx.indexer, "resume_project", lambda name: seen.append(name) or 0)
    assert ctx.bind_session("dirty", pp) is None
    assert seen == ["proj"]


# -- feature ranking, depth and binary filters, summary counts ----------------------------------

def _ranked_feature(st, ids):
    app, lib, _rt = ids
    st.define_feature("rank-demo", "Rank demo", "", "2026-01-01T00:00:00Z")
    rows = [(app, 0x401100, 0, "calls A", "calls A ; calls B"),     # FUN_a: two evidence items
            (app, 0x401200, 0, "calls A", "calls A"),               # FUN_b
            (app, 0x401500, 0, "calls A", "calls A"),               # FUN_cfg
            (lib, 0x1000, 0, "calls A", "calls A"),                 # FUN_lr
            (lib, 0x1100, 1, "caller of FUN_lr", "calls A"),        # Impl
            (app, 0x401300, 2, "caller of FUN_b", "calls A")]       # FUN_c
    with st.db:
        st.db.executemany("INSERT INTO feature_entry(feature_key, binary_id, space, entry, reason, evidence, "
                          "depth, source) VALUES ('rank-demo', ?, 'ram', ?, ?, ?, ?, 'auto')",
                          [(b, e, r, ev, d) for b, e, d, r, ev in rows])


def _fn_names(out):
    return [ln.split(" | ")[1].split(" (")[0] for ln in out.splitlines() if " | auto | " in ln]


def test_feature_seed_first_ranking_and_filters(proj):
    ctx, pp, st = bound(proj)
    ids = proj[3]
    _ranked_feature(st, ids)
    out = mt.feature(ctx, "rank-demo")
    assert out.splitlines()[0] == ("feature rank-demo [agent]: Rank demo | 6 entry points (seeds 4, callers 2) "
                                   "in 2 binaries; named 0 of 6 (0%)")
    assert "by binary: app.exe 4 (seeds 3), lib.dll 2 (seeds 1)" in out
    assert "showing depth 0 only: 4 seeds; depth=1 adds callers (2 more)" in out
    assert _fn_names(out) == ["FUN_a", "FUN_b", "FUN_lr", "FUN_cfg"]      # strength, then binary interleave
    assert _fn_names(mt.feature(ctx, "rank-demo", depth=1)) == ["FUN_a", "FUN_b", "FUN_lr", "FUN_cfg", "Impl"]
    assert _fn_names(mt.feature(ctx, "rank-demo", depth=2))[-1] == "FUN_c"
    lib_only = mt.feature(ctx, "rank-demo", depth=2, binary="LIB.dll")
    assert _fn_names(lib_only) == ["FUN_lr", "Impl"] and "in lib.dll" in lib_only
    assert mt.feature(ctx, "rank-demo", binary="nope.exe").startswith("error not_found: no binary")
    listing = mt.features(ctx)
    assert "rank-demo [agent] | Rank demo | seeds 4, total 6 in 2 binaries | named 0 of 6 (0%) | " in listing
    assert "rank-demo [agent] | Rank demo | seeds 4, total 6 | named 0 of 6 (0%) | " in mt.overview(ctx)


def test_derive_cap_counts_dropped(proj, monkeypatch):
    ctx, pp, st = bound(proj)
    ids = proj[3]
    from airlock.server import features as fx
    full = fx.derive_project(pp, st)["file-io"]
    monkeypatch.setattr(fx, "MAX_ENTRIES", 4)
    capped = fx.derive_project(pp, st)["file-io"]
    assert capped == 4 and full > 4
    assert fx.dropped(st)["file-io"] == full - 4
    out = mt.feature(ctx, "file-io", depth=2)
    assert f"true total at least {full}, list ranked and capped at 4" in out.splitlines()[0]
    assert f"total at least {full}, ranked top 4 listed (cap 4)" in mt.features(ctx)
    seeds = [r for r in fx.stats(st) if r["key"] == "file-io"][0]["seeds"]
    assert seeds == 3                                                    # seeds are kept before callers


# -- overview framework lines ------------------------------------------------------------------------

class _FakeStore:
    def __init__(self, filled):
        import sqlite3
        self.db = sqlite3.connect(":memory:")
        for t in ("dl_class", "qt_class", "msgmap_entry", "dn_type", "rtti_class", "res_dialog"):
            self.db.execute(f"CREATE TABLE {t} (x)")
            if t in filled:
                self.db.execute(f"INSERT INTO {t} VALUES (1)")


def test_framework_lines_names_tools_and_enable_hint():
    from airlock.config.catalog import CATALOG
    st = _FakeStore({"dl_class", "qt_class", "msgmap_entry"})
    on = [t for t, i in CATALOG.items() if i.set not in ("delphi", "dotnet")]
    out = pm.framework_lines(st, on, ["delphi", "dotnet"], ["patch_bytes"])
    assert len(out) == 3
    assert out[0].startswith("Delphi (1 classes): delphi_classes, delphi_forms, delphi_events | off in")
    assert "airlock config --set disabled_sets dotnet" in out[0]
    assert out[1] == "Qt (1 classes): qt_metaobjects"
    assert out[2] == "MFC (1 message map entries): mfc_message_maps, dialogs, menus"
    assert pm.framework_lines(_FakeStore(set()), on, [], []) == []
    res = pm.framework_lines(_FakeStore({"res_dialog"}), on, [], [])
    assert res == ["Win32 resources (1 dialogs): dialogs, menus, string_tables"]


def test_framework_lines_tool_disabled_individually():
    st = _FakeStore({"rtti_class"})
    out = pm.framework_lines(st, ["rtti_classes"], [], ["vtable"])
    assert "off in this profile: vtable" in out[0] and "disabled_tools []" in out[0]


def test_overview_has_frameworks_section(proj):
    ctx, pp, st = bound(proj)
    assert "## Frameworks" not in mt.overview(ctx)
    b = st.list_binaries()[0]
    st.db.execute("INSERT INTO rtti_class (binary_id, name, td_addr, col_addr) VALUES (?, 'CFoo', 1, 2)", (b.id,))
    st.db.commit()
    out = mt.overview(ctx)
    assert "## Frameworks\nC++ RTTI (1 classes): rtti_classes, vtable" in out
