"""function view=asm / view=both: formatting, cache, paging (fake worker, no Ghidra)."""

from __future__ import annotations

import test_tools
from airlock.server.cview import format_asm
from airlock.server.tools import core
from test_tools import ASM_ROWS, ctx  # noqa: F401  (fixture)


def test_format_asm_lines():
    out = format_asm(ASM_ROWS, 4)
    assert out[0] == "0x00401000  PUSH EBP"
    assert "0x00401003  CALL 0x00401100  ; → CMainFrame::OnFoo" in out
    assert '0x0040100c  PUSH 0x403000  ; → "Open file failed"' in out
    i = out.index("LAB_00401012:")
    assert out[i + 1] == "0x00401012  POP EBP" and len(out) == len(ASM_ROWS) + 1
    assert format_asm(ASM_ROWS[:2], 4, 50)[-1] == "; … truncated at 2 of 50 instructions"
    assert format_asm([[0x140001000, 1, "RET", "", "", 1]], 8) == ["0x0000000140001000  RET"]


def test_view_asm_output_and_cache(ctx):  # noqa: F811
    out = core.function(ctx, "main", view="asm")
    ls = out.splitlines()
    assert ls[0] == "// main 0x00401000 asm: lines 1-9"
    assert ls[1] == "0x00401000  PUSH EBP" and "LAB_00401012:" in ls
    assert ctx.worker.count("disassemble") == 1
    assert core.function(ctx, "0x00401000", view="asm") == out     # cached on disk
    assert ctx.worker.count("disassemble") == 1
    # a version bump invalidates the cache
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    st.insert_functions(b.id, [{"entry": 0x401000, "name": "main", "name_state": "user", "size": 0x44}])
    core.function(ctx, "main", view="asm")
    assert ctx.worker.count("disassemble") == 2
    assert core.function(ctx, "main", view="asm", lines="2-3").splitlines()[1:] == [
        "0x00401001  MOV EBP,ESP", "0x00401003  CALL 0x00401100  ; → CMainFrame::OnFoo"]
    assert core.function(ctx, "main", view="asm", lines="50-60").startswith("error bad_args:")
    assert core.function(ctx, "EXTERNAL:0x1", view="asm").startswith("error external:")


def test_view_asm_cursor_paging(ctx):  # noqa: F811
    rows = [[0x401000 + i, 1, "NOP", "", "", int(i == 0)] for i in range(300)]
    orig = test_tools.ASM_ROWS[:]
    test_tools.ASM_ROWS[:] = rows
    try:
        first = core.function(ctx, "main", view="asm", budget=200)
    finally:
        test_tools.ASM_ROWS[:] = orig
    ls = first.splitlines()
    assert ls[-1].startswith("… ") and "more lines. cursor=c_" in ls[-1]
    cid = ls[-1].split("cursor=")[1]
    nxt = core.function(ctx, "main", view="asm", cursor=cid, budget=200).splitlines()
    shown = len(ls) - 2
    assert nxt[0] == f"0x{0x401000 + shown:08x}  NOP"
    assert core.function(ctx, "main", view="asm", cursor="c_dead").startswith("error bad_cursor:")
    assert core.function(ctx, "OnFoo", view="asm", cursor=cid).startswith("error bad_cursor:")


def test_view_both_c_then_asm(ctx):  # noqa: F811
    out = core.function(ctx, "main", view="both")
    ls = out.splitlines()
    assert ls[0] == "// C" and ls[1] == "void main(void)"
    k = ls.index("// asm (9 lines)")
    assert ls[k - 1] == "}" and ls[k + 1] == "0x00401000  PUSH EBP"
    assert "OnFoo/*0x00401100*/();" in out
    assert core.function(ctx, "main", view="both", lines="1-2").startswith("error bad_args:")
    assert core.function(ctx, "main", view="x").startswith("error bad_args:")
    assert core.function(ctx, "main", outline_depth=9).startswith("error bad_args:")
