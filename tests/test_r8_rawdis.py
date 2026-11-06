"""function on a code address with no Ghidra function and no way to create one: raw disassembly (fake worker)."""

from __future__ import annotations

from airlock.server import cpp, roles
from airlock.server.tools import core
from test_r8g import _prog


def _setup(tmp_path, monkeypatch, writes=False):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "qt")
    text = cpp.Section(base + 0x1000, b"\0" * 0x2000, True, 0x2000)
    data = cpp.Section(base + 0x3000, b"\0" * 0x100, False, 0x100)
    img = cpp.Image(4, base, [text, data])
    monkeypatch.setattr(cpp.Image, "from_pe", classmethod(lambda cls, p: img))
    monkeypatch.setattr(ctx.indexer, "ensure_open", lambda p: None)
    ctx.config.allow_writes = writes
    return ctx, base


def test_raw_view_when_writes_off(tmp_path, monkeypatch):
    ctx, base = _setup(tmp_path, monkeypatch)
    addr = base + 0x1c00
    out = core.function(ctx, f"0x{addr:08x}", view="asm").splitlines()
    assert out[0].startswith(f"// no function at 0x{addr:08x}; disassembly from there to the first RET or unconditional JMP")
    assert out[1].endswith("PUSH EBP")
    call = [a for o, a in ctx.worker.calls if o == "disassemble"][0]
    assert call["raw"] is True and call["entry"] == addr and call["max_instructions"] == core.RAW_MAX
    assert not any(o == "create_functions" for o, _ in ctx.worker.calls)
    assert core.function(ctx, f"0x{addr:08x}").splitlines()[1] == out[1]            # view=c shows the same
    assert core.function(ctx, f"0x{addr:08x}", view="signature").startswith("error not_found")


def test_raw_view_not_for_data_or_clean_role(tmp_path, monkeypatch):
    ctx, base = _setup(tmp_path, monkeypatch)
    r = core.function(ctx, f"0x{base + 0x3010:08x}", view="asm")                      # data block
    assert r.startswith("error not_found") and not ctx.worker.count("disassemble")
    ctx.session = roles.SessionState(roles.CLEAN, ctx.session.project)
    r = core.function(ctx, f"0x{base + 0x1c00:08x}", view="asm")                      # clean: never code
    assert r.startswith("error not_found") and not ctx.worker.count("disassemble")


def test_raw_view_worker_refuses(tmp_path, monkeypatch):
    from airlock.worker.protocol import WorkerError
    ctx, base = _setup(tmp_path, monkeypatch)
    ctx.worker.fail_op = "disassemble"
    r = core.function(ctx, f"0x{base + 0x1c00:08x}", view="asm")
    assert r.startswith("error not_found")
