"""Tools take the next step themselves instead of advising it (DESIGN 7.5): close-name resolution,
candidates as data, forwarding, widening. Synthetic stores, invented names."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from airlock.server import registry
from airlock.server import selectors
from airlock.server import targets as tg
from airlock.server.tools import annotate as an
from airlock.server.tools import core
from airlock.server.tools import cpp as _cpp_tools  # noqa: F401  registers rtti_classes
from airlock.server.tools import fileformat as fft
from airlock.server.tools import fmap
from airlock.server.tools import graphtools as gt
from airlock.worker.protocol import WorkerError
from test_fileformat import env  # noqa: F401  fixture
from test_graphtools import proj  # noqa: F401  fixture
from test_targets import world  # noqa: F401  fixture
from test_tools import ctx  # noqa: F401  fixture
from cfb import build_cfb


# -- names: case differs -> resolved; near names -> listed ---------------------------------------

def test_name_with_other_case_resolves_with_a_note(world):  # noqa: F811
    c = world[0]
    out = core.function(c, "host.exe!reader", view="signature").splitlines()
    assert out[0] == "resolved 'reader' to Reader (case differs)"
    assert out[1].startswith("0x00401100 Reader")
    t = tg.resolve_target(c, "", "solo", (tg.FUNCTION,))      # every binary: the one hit, its binary
    assert isinstance(t, tg.FunctionTarget) and t.fn.name == "Solo" and t.binary_note == "binary tool.exe"


def test_not_found_lists_close_names(world):  # noqa: F811
    c = world[0]
    out = core.xrefs(c, "Writ")
    assert out == ("error not_found: no function or import named 'Writ' in 3 ready binaries. "
                   "close names: host.exe!Writer 0x00401200.")
    assert core.xrefs(c, "Zq").endswith("in 3 ready binaries.")      # too short to guess: no list


def test_case_resolution_never_picks_between_several(world):  # noqa: F811
    c = world[0]
    out = core.xrefs(c, "main")             # Main in host.exe and tool.exe: a choice, so listed
    assert out.startswith("error not_found: no function or import named 'main'")
    assert "host.exe!Main 0x00401000" in out and "tool.exe!Main 0x00501000" in out


def test_selectors_close_functions(world):  # noqa: F811
    c, st, ids = world
    r = selectors.resolve_function(st, ids["host.exe"], "WRITER")
    assert r.function is not None and r.function.name == "Writer" and "case differs" in (r.note or "")
    r = selectors.resolve_function(st, ids["host.exe"], "rite")
    assert r.function is None and r.error == "error not_found: no function named 'rite'. close names: Writer 0x00401200."


# -- data instead of advice ----------------------------------------------------------------------

def test_unbound_lists_projects(ctx):  # noqa: F811
    assert registry.call(ctx, "strings", pattern="x") == "error unbound: no project is open. projects: proj."


def test_binary_and_project_choices_are_listed(world):  # noqa: F811
    c = world[0]
    assert core.outline(c) == ("error ambiguous_binary: project 'proj' has 3 binaries: "
                               "host.exe, plug.dll, tool.exe.")
    assert core.list_binaries(c, project="nope") == "error no_project: project 'nope' does not exist (have: proj)."


# -- the tool does the step ----------------------------------------------------------------------

def test_interrupted_binary_is_queued_again(ctx, monkeypatch):  # noqa: F811
    ix = ctx.indexer
    st = ix.store("proj")
    b2 = st.upsert_binary("cd" * 32, "other.dll", pointer_size=4)
    ix.set_status(st, b2, "analysing")                  # no job: the server stopped mid-analysis
    queued = []
    monkeypatch.setattr(ix, "enqueue", lambda p, files: queued.extend(files) or ["other.dll"])
    out = core.strings(ctx, "open", binary="other.dll")
    assert out.startswith("error not_analysed:") and "interrupted" in out and "resumed" not in out  # no artifact
    art = ix.paths("proj").artifacts / ("cd" * 32)
    art.parent.mkdir(parents=True, exist_ok=True)
    art.write_bytes(b"MZ")
    out = core.strings(ctx, "open", binary="other.dll")
    assert out.endswith("; resumed after a server stop).") and queued[0]["sha256"] == "cd" * 32


def test_search_forwards_unindexed_kinds(ctx, monkeypatch):  # noqa: F811
    assert ctx.bind_session("dirty", ctx.indexer.paths("proj")) is None
    out = core.search(ctx, "CMainFrame", kind="class")
    assert out.splitlines()[0] == "(rtti_classes used for kind=class)"
    monkeypatch.setattr(ctx.config, "tools", [t for t in ctx.config.tools if t != "rtti_classes"])
    assert core.search(ctx, "x", kind="class") == (
        "error not_supported: kind 'class' needs rtti_classes, which is off in config.jsonc.")


def test_label_outside_a_function_is_named_as_global(monkeypatch):
    calls = []
    bd = SimpleNamespace(project="p", psize=4, binary=SimpleNamespace(id=1, name="a.exe", format="pe32",
                                                                      toolchain="msvc"),
                         addr=lambda v, s="ram": f"0x{v:08x}")
    st = SimpleNamespace(function_containing=lambda *a: None, functions_referencing=lambda *a: [],
                         bump_versions=lambda ids: None)
    bd.store = st
    sc = SimpleNamespace(bounds=[bd], bare="0x00402000")
    monkeypatch.setattr(an, "bind_scope", lambda ctx, b, t: sc)
    monkeypatch.setattr(an, "_worker", lambda ctx, b, op, args: (calls.append((op, args)) or
                                                                 {"address": 0x402000, "old": "DAT_00402000"}, None))
    monkeypatch.setattr(an.dn, "is_managed_only", lambda b: False)
    monkeypatch.setattr(an.dn, "is_managed_site", lambda b, s, v: False)
    out = an._rename_label(SimpleNamespace(), "0x00402000", "g_table", "label", "")
    assert out.splitlines()[0] == "(kind=global used: 0x00402000 is not inside a function)"
    assert out.splitlines()[1].startswith("renamed global DAT_00402000 -> g_table at 0x00402000")
    assert calls[0][0] == "rename_label"


def test_write_retries_a_failed_decompile_once():
    tries = []

    def request(op, args, timeout=0):
        tries.append(op)
        if len(tries) == 1:
            raise WorkerError("decompile_failed", "decompiler busy")
        return {"ok": True}

    ctx = SimpleNamespace(indexer=SimpleNamespace(ensure_open=lambda p: None, program_of=lambda s, b: "x"),
                          worker=SimpleNamespace(request=request))
    bd = SimpleNamespace(project="p", store=None, binary=None)
    assert an._worker(ctx, bd, "retype_variable", {}) == ({"ok": True}, None) and len(tries) == 2
    tries.clear()

    def always(op, args, timeout=0):
        tries.append(op)
        raise WorkerError("decompile_failed", "took too long")

    ctx.worker.request = always
    _r, err = an._worker(ctx, bd, "retype_variable", {})
    assert len(tries) == 2 and err == ("error decompile_failed: took too long. "
                                       "the limit is defaults.decompile_timeout_s in config.jsonc.")
    ctx.worker.request = lambda op, args, timeout=0: (_ for _ in ()).throw(WorkerError("exists", "name taken"))
    assert an._worker(ctx, bd, "rename_function", {})[1] == "error exists: name taken."


def test_retype_excerpt_follows_a_variable_renamed_by_type():
    c = "void f(void)\n{\n  Rec *pRVar1;\n  pRVar1 = g();\n  use(pRVar1->n);\n}\n"
    out = an._excerpt(c, "local_10", "Rec *").splitlines()
    assert out[0] == "no line names 'local_10' now (renamed by type); lines with Rec:"
    assert out[1] == "    3    Rec *pRVar1;"
    assert an._excerpt(c, "local_10", "") == ("no decompile line names 'local_10' now (the decompiler "
                                             "renames automatic variables by type)")


# -- path / function_map widen or follow ---------------------------------------------------------

def test_path_follows_a_thunk_to_its_import(proj):  # noqa: F811
    c = proj[0]
    out = gt.path(c, "Boot", "app.exe!0x00020000")       # PlugOpen thunk: no graph node of its own
    assert out.splitlines()[0].startswith(
        "path Boot → app.exe!0x00020000 (import PLUG!PlugOpen, followed from the thunk), ")


def test_function_map_scope_of_a_thunk_and_an_empty_scope(proj):  # noqa: F811
    c = proj[0]
    out = fmap.function_map(c, scope="app.exe!0x00020000")
    assert "PlugOpen is not clustered (thunk, external or runtime); called from " in out
    whole = fmap.function_map(c)
    st = c.indexer.store("proj")      # a binary with no clusters as scope: the whole map, said so
    st.upsert_binary("ee" * 32, "empty.dll", pointer_size=4, analysis_profile="p1")
    out = fmap.function_map(c, scope="empty.dll")
    assert "(no subsystem matches scope 'empty.dll': whole map)" in out
    assert out.count("\n") >= whole.count("\n")


# -- files: same-name candidates, stream ignored, stream list ------------------------------------

def test_file_not_found_lists_same_name_files(env):  # noqa: F811
    c, src, _ = env
    (src / "sub").mkdir()
    (src / "sub" / "data.bin").write_bytes(b"x")
    out = fft.resolve_path(c, "data.bin")
    assert isinstance(out, str) and out.endswith("Files with that name: sub\\data.bin.")
    assert fft.resolve_path(c, "sub\\data.bin") == (src / "sub" / "data.bin").resolve()


def test_file_diff_ignores_stream_for_plain_files(env):  # noqa: F811
    c, src, _ = env
    (src / "a.bin").write_bytes(b"abcd")
    (src / "b.bin").write_bytes(b"abce")
    out = fft.file_diff(c, "a.bin", "b.bin", stream="Root/X")
    assert out.startswith("(stream ignored: not two OLE files) diff a.bin 4B vs b.bin 4B: ")


def test_missing_ole_stream_lists_the_streams(env):  # noqa: F811
    c, src, _ = env
    (src / "a.doc").write_bytes(build_cfb({"WordDocument": b"w" * 4096, "Data": b"d" * 4096}))
    out = registry.call(c, "ole_streams", path="a.doc", stream="nope")
    assert out.startswith("error not_found: no stream 'nope' in a.doc (have: ") and "WordDocument" in out


@pytest.mark.parametrize("bad", ["Pass retry=true to try again.", "Call index_status."])
def test_errors_end_with_data_not_orders(bad, world):  # noqa: F811
    c = world[0]
    for out in (core.xrefs(c, ""), core.function(c, "host.exe!Nope"), core.callgraph(c, "x", direction="up"),
                core.strings(c, ""), core.search(c, "")):
        assert out.startswith("error ") and bad not in out and "\n" not in out
