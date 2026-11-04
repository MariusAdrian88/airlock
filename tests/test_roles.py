"""Session roles, tool gating, project_create, manifest and deny rules (no Ghidra)."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest

from airlock import projects as P
from airlock.config.loader import deep_merge, default_config_text, parse_jsonc, resolve
from airlock.server import roles
from airlock.server.app import build_server
from airlock.server.scan import ScanOption, ScannedFile, ScanResult
from airlock.server.tools import project_create as pc
from test_tools import make_ctx


def _cfg(tmp_path, profile="dirty"):
    merged = deep_merge(parse_jsonc(default_config_text()),
                        {"ghidra_dir": str(tmp_path / "g"), "index_dir": str(tmp_path / "d"),
                         "projects_root": str(tmp_path / "projects")})
    return resolve(merged, profile, None)


def make_project(root: Path, name="demo") -> P.ProjectPaths:
    return P.project_paths(root, name, create=True)


# -- config / layout / manifest ------------------------------------------------

def test_projects_root_config(tmp_path):
    assert _cfg(tmp_path).projects_root == tmp_path / "projects"
    merged = deep_merge(parse_jsonc(default_config_text()), {"ghidra_dir": "x"})
    assert resolve(merged, "dirty", None).projects_root.name == "airlock-projects"
    with pytest.raises(Exception, match="absolute"):
        resolve(deep_merge(merged, {"projects_root": "rel/dir"}), "dirty", None)


def test_manifest_round_trip(tmp_path):
    f = tmp_path / "m" / P.MANIFEST_NAME
    data = {"name": "x", "files": [{"path": "a b.exe", "sha256": "ab"}]}
    P.write_manifest(f, data)
    assert f.read_text("utf-8").startswith("//")
    assert P.read_manifest(f) == data


# -- gating and session tools ---------------------------------------------------------

def _call(server, name, args=None):
    async def go():
        return (await server.call_tool(name, args or {})).content[0].text
    return anyio.run(go)


def _server(tmp_path, profile="dirty", explicit=False):
    pp = make_project(tmp_path / "projects")
    man = P.read_manifest(pp.manifest)
    man.update({"source": {"root_exe": "app.exe"}, "files": [
        {"path": "app.exe", "kind": "pe", "state": "ready"},
        {"path": "a.dll", "kind": "pe", "state": "queued"},
        {"path": "d.bin", "kind": "data", "state": "queued"}]})
    P.write_manifest(pp.manifest, man)
    (pp.specs / "one.md").write_text("x")
    server, ctx = build_server(_cfg(tmp_path, profile), profile_explicit=explicit)
    return server, ctx, pp


@pytest.mark.parametrize("tool", ["open_binary", "function", "index_status", "spec_write"])
def test_unbound_blocks_other_tools(tool):
    assert roles.gate(roles.SessionState(), tool).startswith("error unbound:")


@pytest.mark.parametrize("tool", ["projects", "project_open", "project_create", "program_scan",
                                  "project_info"])
def test_unbound_allows(tool):
    assert roles.gate(roles.SessionState(), tool) is None


def test_clean_gate(tmp_path):
    s = roles.SessionState(roles.CLEAN, make_project(tmp_path))
    for t in ("spec_read", "spec_list", "spec_export", "projects", "project_info"):
        assert roles.gate(s, t) is None
    for t in ("function", "program_scan", "spec_write"):
        assert roles.gate(s, t).startswith("error wrong_role:")
    for t in ("project_open", "project_create"):
        assert roles.gate(s, t).startswith("error role_locked:")


def test_dirty_gate(tmp_path):
    s = roles.SessionState(roles.DIRTY, make_project(tmp_path))
    assert roles.gate(s, "function") is None and roles.gate(s, "program_scan") is None
    for t in ("project_open", "project_create"):
        assert roles.gate(s, t).startswith("error role_locked:")


def test_new_session_is_unbound(tmp_path):
    server, ctx, pp = _server(tmp_path)
    assert ctx.session.role == "unbound"
    assert _call(server, "function", {"query": "x"}).startswith("error unbound:")
    assert not pp.index_db.exists()


def test_projects_lists_full_when_not_clean(tmp_path):
    server, ctx, pp = _server(tmp_path)
    assert _call(server, "projects") == (
        f"demo | root app.exe | binaries 1 ready/1 queued | specs 1 | {pp.root}")


def test_project_open_dirty_then_locked(tmp_path):
    server, ctx, pp = _server(tmp_path)
    out = _call(server, "project_open", {"name": "demo", "role": "dirty"})
    assert out.splitlines()[0] == (
        f"session dirty for demo: write notes and scratch files only under {pp.dirty}")
    assert out.splitlines()[1] == "binaries: 1 ready, 1 queued"
    assert ctx.session.role == "dirty" and ctx.indexer.current == "demo"
    locked = ("error role_locked: this session is already dirty for demo. "
              "Start a new session for other work.")
    assert _call(server, "project_open", {"name": "demo", "role": "clean"}) == locked
    assert _call(server, "project_open", {"name": "nope", "role": "dirty"}) == locked
    assert _call(server, "project_create", {"path": str(tmp_path), "name": "z"}) == locked
    assert ctx.session.role == "dirty"


def test_project_open_clean_and_redaction(tmp_path):
    server, ctx, pp = _server(tmp_path)
    out = _call(server, "project_open", {"name": "demo", "role": "clean"})
    assert out.splitlines()[0] == (f"session clean for demo: write the implementation under {pp.clean}; "
                                   f"never read {pp.dirty}. Specs: 1 published in {pp.specs}")
    assert "# demo (clean map)" in out and "one" in out and "app.exe" not in out
    assert _call(server, "projects") == "demo | specs 1"
    info = _call(server, "project_info")
    assert "role clean | project demo" in info
    for leak in (str(tmp_path), "app.exe", "ghidra", "jdk", "config"):
        assert leak not in info
    assert "function" not in info.replace("spec_read", "")
    assert _call(server, "function", {"query": "x"}).startswith("error wrong_role:")
    assert _call(server, "project_open", {"name": "demo", "role": "dirty"}).startswith(
        "error role_locked:")


def test_project_open_errors(tmp_path):
    server, ctx, _ = _server(tmp_path)
    assert _call(server, "project_open", {"name": "nope", "role": "dirty"}).startswith(
        "error not_found: no project 'nope'. Call projects")
    assert _call(server, "project_open", {"name": "demo", "role": "x"}).startswith("error bad_role:")
    assert ctx.session.role == "unbound"  # failures do not bind
    assert _call(server, "project_open", {"name": "DEMO", "role": "Dirty"}).startswith("session dirty")


def test_profile_mismatch(tmp_path):
    server, ctx, _ = _server(tmp_path, "clean", explicit=True)
    assert _call(server, "project_open", {"name": "demo", "role": "dirty"}) == (
        "error wrong_role: this server was started with --profile clean.")
    assert ctx.session.role == "unbound"
    assert _call(server, "projects") == "demo | specs 1"  # clean profile redacts when unbound too
    assert _call(server, "project_open", {"name": "demo", "role": "clean"}).startswith("session clean")
    server, ctx, _ = _server(tmp_path / "b", "dirty", explicit=True)
    assert _call(server, "project_open", {"name": "demo", "role": "dirty"}).startswith("session dirty")
    server, ctx, _ = _server(tmp_path / "c", "dirty")  # not explicit: no restriction
    assert _call(server, "project_open", {"name": "demo", "role": "clean"}).startswith("session clean")


def test_clean_profile_lists_session_tools_only(tmp_path):
    server, _ = build_server(_cfg(tmp_path, "clean"))
    names = {t.name for t in anyio.run(server.list_tools)}
    assert names == {"projects", "project_open", "project_info", "spec_read", "spec_list",
                     "spec_export"}


# -- project_create ------------------------------------------------------------------

def _sf(rel, group, kind="pe", code=1 << 20, dll=False):
    pe = kind == "pe"
    return ScannedFile(rel, kind, group, 2 << 20 if pe else 10, code if pe else 0,
                       32 if pe else None, dll, False, False, None, None, (), 0)


@pytest.fixture
def fake_scan(tmp_path, monkeypatch):
    src = tmp_path / "prog"
    (src / "plug").mkdir(parents=True)
    for rel, body in {"app.exe": b"A" * 100, "core.dll": b"B" * 100, "plug/p1.dll": b"C" * 100,
                      "data.bin": b"D" * 10}.items():
        (src / rel).write_bytes(body)
    app, core = _sf("app.exe", "core"), _sf("core.dll", "core", dll=True)
    plug, data = _sf("plug/p1.dll", "own_plugin", dll=True), _sf("data.bin", "data", kind="data")
    a = ScanOption("A", "Core", ("core",), (app, core), 2 << 20, 160.0)
    b = ScanOption("B", "Core + own plugins", ("core", "own_plugin"), (app, core, plug),
                   3 << 20, 240.0)
    res = ScanResult(src, "app.exe", "largest executable", (app, core, plug, data), (), (),
                     (a, b), "B")
    monkeypatch.setattr(pc, "scan_program", lambda path, root_exe=None, s_per_code_mb=120.0, overhead_s=20.0: res)
    monkeypatch.setattr(pc, "render_scan", lambda r: ["SCANTABLE"])
    return src


def test_project_create_need_name(tmp_path, fake_scan):
    ctx = make_ctx(tmp_path)
    out = pc.project_create(ctx, str(fake_scan))
    assert out.startswith("error need_name:") and "name=" in out


def test_project_create_table_then_create_then_exists(tmp_path, fake_scan):
    ctx = make_ctx(tmp_path)
    out = pc.project_create(ctx, str(fake_scan), name="My Prog")
    assert out.splitlines()[0] == "SCANTABLE"
    assert "Choose option=A..B (recommended B)" in out
    assert not (tmp_path / "projects" / "My_Prog").exists()

    out = pc.project_create(ctx, str(fake_scan), name="My Prog", option="b", remove="core.dll",
                            add="data.bin")
    root = tmp_path / "projects" / "My_Prog"
    assert out.splitlines()[-2] == (
        f"session dirty for My_Prog: write notes and scratch files only under {root / 'dirty'}")
    assert ctx.session.role == "dirty" and ctx.session.project.name == "My_Prog"
    assert "Open the MCP client" not in out
    man = P.read_manifest(root / P.MANIFEST_NAME)
    assert man["selected_option"] == "B" and man["source"]["root_exe"] == "app.exe"
    paths = {f["path"]: f for f in man["files"]}
    assert set(paths) == {"app.exe", "plug/p1.dll", "data.bin"}
    assert paths["plug/p1.dll"]["group"] == "own_plugin" and len(paths["app.exe"]["sha256"]) == 64
    assert paths["plug/p1.dll"]["state"] == "error"  # every PE is enqueued; the fake file is no PE
    assert paths["app.exe"]["state"] == "error"  # fake file is not a PE: indexer refuses it
    for f in man["files"]:
        assert (root / "dirty" / ".airlock" / "artifacts" / f["sha256"]).is_file()
    assert (root / "clean" / "specs").is_dir()
    assert pc.project_create(ctx, str(fake_scan), name="my prog!", option="A").startswith("error exists:")
    assert pc.project_create(ctx, str(fake_scan), name="q", option="Z").startswith("error bad_option:")
    assert pc.project_create(ctx, str(fake_scan), name="q", option="A",
                             add="nope.dll").startswith("error bad_file:")


def test_project_create_enqueues_all_pe_files(tmp_path, fake_scan, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = []
    monkeypatch.setattr(ctx.indexer, "enqueue", lambda slug, files: calls.append((slug, files)) or [])
    monkeypatch.setattr(ctx.indexer, "open_binary", lambda *a, **k: pytest.fail("open_binary used"))
    pc.project_create(ctx, str(fake_scan), name="q", option="B")
    assert calls and calls[0][0] == "q"  # later calls are resume_project at bind
    assert [f["path"] for f in calls[0][1] if f["kind"] == "pe"] == [
        "app.exe", "core.dll", "plug/p1.dll"]
    assert all(len(f["sha256"]) == 64 for f in calls[0][1])
    man = P.read_manifest(tmp_path / "projects" / "q" / P.MANIFEST_NAME)
    assert {f["path"]: f["state"] for f in man["files"]} == {
        "app.exe": "queued", "core.dll": "queued", "plug/p1.dll": "queued"}


def test_deny_rules(tmp_path):
    pp = make_project(tmp_path)
    P.write_clean_deny_rules(pp)
    rule = "//" + str(pp.dirty.resolve()).replace("\\", "/")
    cs = json.loads((pp.clean / ".claude" / "settings.json").read_text("utf-8"))
    assert cs == {"permissions": {"deny": [f"Read({rule}/**)", f"Edit({rule}/**)"]}}
    assert json.loads((pp.clean / "opencode.json").read_text("utf-8")) == {
        "permission": {"external_directory": {"*": "deny"}}}
    toml = (pp.clean / ".codex" / "config.toml").read_text("utf-8")
    assert 'default_permissions = "airlock-clean"' in toml and "dirty/**" in toml


def test_deny_rules_merge_and_keep_existing(tmp_path):
    pp = make_project(tmp_path)
    cj = pp.clean / ".claude" / "settings.json"
    cj.parent.mkdir(parents=True)
    cj.write_text(json.dumps({"permissions": {"deny": ["Read(secret)"], "allow": ["Bash(ls)"]},
                              "x": 1}))
    (pp.clean / ".codex").mkdir()
    (pp.clean / ".codex" / "config.toml").write_text("mine = true\n")
    P.write_clean_deny_rules(pp)
    cs = json.loads(cj.read_text("utf-8"))
    assert cs["x"] == 1 and cs["permissions"]["allow"] == ["Bash(ls)"]
    assert cs["permissions"]["deny"][0] == "Read(secret)" and len(cs["permissions"]["deny"]) == 3
    P.write_clean_deny_rules(pp)  # idempotent
    assert len(json.loads(cj.read_text("utf-8"))["permissions"]["deny"]) == 3
    assert (pp.clean / ".codex" / "config.toml").read_text() == "mine = true\n"
