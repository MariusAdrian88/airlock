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


def test_patch_bytes_real_program(world):
    """patch_bytes writes the Ghidra program only: the asm view changes, the original file does not,
    a cut instruction and unmapped memory are refused, restore=<note> puts the old bytes back."""
    import hashlib
    from pathlib import Path

    st, _caller, fn = _pair(world)
    b = st.list_binaries()[0]
    prog = world.indexer.program_of(st, b)
    rows = world.worker.request("disassemble", {"program": prog, "entry": fn.entry,
                                                "max_instructions": 8}, timeout=300)["rows"]
    first = rows[0]
    multi = next((r for r in rows[1:] if r[1] >= 2), None)
    assert first[0] == fn.entry
    file_hash = hashlib.sha256(Path(b.original_path).read_bytes()).hexdigest() if b.original_path else None
    def code(view_text):
        return [ln for ln in view_text.splitlines() if ln.startswith("0x")]

    asm0 = code(core.function(world, f"0x{fn.entry:x}", view="asm"))
    nops = "90" * first[1]
    out = an.patch_bytes(world, f"0x{fn.entry:x}", nops, why="ghidra test")
    assert out.startswith(f"patched {first[1]} bytes at 0x"), out
    nid = int(out.split("note #")[1].split(";")[0])
    asm1 = code(core.function(world, f"0x{fn.entry:x}", view="asm"))
    assert asm1 != asm0 and "NOP" in asm1[0].upper(), asm1[:3]
    if multi is not None:                                    # one byte inside a later multi-byte instruction
        assert an.patch_bytes(world, f"0x{multi[0] + 1:x}", "90").startswith("error boundary")
    assert an.patch_bytes(world, "0x7ffffff0", "90").startswith("error uninitialized")
    def raw():
        return world.worker.request("disassemble", {"program": prog, "entry": fn.entry, "max_instructions": 1},
                                    timeout=300)["rows"][0][2]
    assert raw() == "NOP", raw()
    back = an.patch_bytes(world, restore=nid)
    assert raw() != "NOP", (raw(), back)
    assert back.startswith("patched ") and "(restore" not in back.split(";")[0], back
    assert code(core.function(world, f"0x{fn.entry:x}", view="asm")) == asm0, (world.worker.request("disassemble", {"program": prog, "entry": fn.entry, "max_instructions": 3}, timeout=300)["rows"], back)
    if file_hash:
        assert hashlib.sha256(Path(b.original_path).read_bytes()).hexdigest() == file_hash
