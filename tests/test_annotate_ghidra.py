"""annotate tools against the real worker (JVM + Ghidra, minutes).

    pytest -q -m ghidra --binary=<path-to-exe>

Works on a fresh project built in a temp folder from the given exe, so nothing outside it changes.
Asserts generic properties only.
"""

from __future__ import annotations

import dataclasses
import time

import pytest

from airlock.config.loader import load_config
from airlock.server.context import ServerContext
from airlock.server.tools import admin, annotate as an, core
from airlock.worker.client import WorkerClient

pytestmark = pytest.mark.ghidra
READY_WAIT_S = 1800


@pytest.fixture(scope="module")
def world(binary_path, tmp_path_factory):
    cfg = dataclasses.replace(load_config(), data_dir=tmp_path_factory.mktemp("data"),
                              projects_root=tmp_path_factory.mktemp("projects"))
    cfg.defaults["bulk_decompile"] = "lazy"
    ctx = ServerContext(config=cfg, worker=WorkerClient(cfg))
    try:
        out = core.open_binary(ctx, "ann", binary_path)
        assert "error" not in out.splitlines()[0], out
        deadline = time.monotonic() + READY_WAIT_S
        status = ""
        while time.monotonic() < deadline:
            status = admin.index_status(ctx)
            if " ready:" in status or " error:" in status:
                break
            time.sleep(2)
        assert " ready:" in status, status
        yield ctx
    finally:
        ctx.worker.stop()


def _pair(ctx):
    """(caller, callee): an auto-named, non-thunk callee with an auto-named caller that decompiles."""
    st = ctx.indexer.store("ann")
    b = st.list_binaries()[0]
    for fn in st.list_functions(b.id, name_state="auto", limit=5000):
        if fn.is_thunk or fn.is_external or fn.space != "ram" or not fn.name.startswith("FUN_"):
            continue
        for c in st.callers(fn, 10):
            if c.name.startswith("FUN_") and c.id != fn.id and not c.is_thunk:
                return st, c, fn
    pytest.skip("no auto-named caller/callee pair in this binary")


def test_rename_callee_refreshes_caller_decompile(world):
    st, caller, callee = _pair(world)
    before = core.function(world, f"0x{caller.entry:x}")
    assert not before.startswith("error"), before
    assert callee.name in before or f"{callee.entry:x}" in before
    out = an.rename(world, f"0x{callee.entry:x}", "AirlockRenamedCallee")
    assert out.startswith("renamed "), out
    after = core.function(world, f"0x{caller.entry:x}")
    assert "AirlockRenamedCallee" in after, after
    assert callee.name not in after
    # persisted in Ghidra: the next extraction (a fresh read of the program) sees the name
    rows = world.worker.request("extract", {"program": world.indexer.program_of(st, st.list_binaries()[0]),
                                            "kind": "functions", "offset": 0, "limit": 20000}, timeout=600)
    names = {r[rows["columns"].index("name")] for r in rows["rows"]}
    assert "AirlockRenamedCallee" in names


def test_annotate_note_comment_and_mirror(world):
    st, caller, _callee = _pair(world)
    out = an.annotate(world, f"0x{caller.entry:x}", "Ghidra test note", tags="t1", confidence="low")
    assert out.startswith("note #"), out
    assert "note #" in core.function(world, f"0x{caller.entry:x}", view="signature")
    assert "Ghidra test note" in core.function(world, f"0x{caller.entry:x}")   # plate mirror in the C
    assert "comment set" in an.comment(world, f"0x{caller.entry:x}", "plate text", kind="plate")
    assert "Ghidra test note" in core.function(world, f"0x{caller.entry:x}")   # block kept


def test_struct_define_and_retype(world):
    out = an.struct_define(world, "AirlockTestRec", [
        {"offset": 0, "type": "int", "name": "a"}, {"offset": 8, "type": "char *", "name": "p"}], size=16)
    assert out.startswith("struct AirlockTestRec created"), out
    out = an.struct_define(world, "AirlockTestRec", [{"offset": 0, "type": "int", "name": "a"}])
    assert "replaced" in out, out
    st, caller, _ = _pair(world)
    text = core.function(world, f"0x{caller.entry:x}")
    import re
    m = re.search(r"\b(local_[0-9a-f]+|param_\d+)\b", text)
    if m:
        r = an.retype(world, f"0x{caller.entry:x}", m.group(1), "AirlockTestRec *")
        assert r.startswith("retyped "), r
        bad = an.retype(world, f"0x{caller.entry:x}", m.group(1), "no_such_type_t")
        assert bad.startswith("error bad_type"), bad
    assert an.rename(world, "nope_not_a_variable", "x", kind="local",
                     function=f"0x{caller.entry:x}").startswith("error no_variable")
