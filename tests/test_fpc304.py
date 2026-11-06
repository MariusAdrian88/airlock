"""Free Pascal 3.0.4 layout differences (**[verified]** with 3.0.4 i386-win32 and x86_64-win64 programs)."""
from __future__ import annotations

import struct

import pytest

from airlock.server import cpp
from airlock.server import targets as tg
from tests.test_r8g import _Info, _patch_image, _prog


@pytest.mark.parametrize("fields,field_of_main", [([1, 2, 3, "pm", 0, 0, 0, 5], 3), ([1, 2, 3, 4, 0, "pm", 0, 5], 5)])
def test_main_x86_record_field_by_version(tmp_path, monkeypatch, fields, field_of_main):
    """``PascalMain`` is field 3 of ``TEntryInformation`` in FPC 3.0.4 and field 5 in FPC 3.2.2."""
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "fpc", 4)
    rec = base + 0x4010
    _patch_image(monkeypatch, base, ent, rec, 4, [pm if f == "pm" else f for f in fields])
    t = tg.resolve_target(ctx, "", "main", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == pm
    assert "PASCALMAIN" in t.note


def test_main_without_a_ghidra_function_resolves_to_its_address(tmp_path, monkeypatch):
    """Ghidra made no function at PASCALMAIN (FPC 3.2.2 console program, **[verified]**): ``main`` is the address."""
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "fpc", 4)
    rec, bare = base + 0x4010, base + 0x1f00
    _patch_image(monkeypatch, base, ent, rec, 4, [1, 2, 3, 4, 0, bare, 0, 5])
    t = tg.resolve_target(ctx, "", "main", (tg.FUNCTION, tg.IMPORT_FN))       # on-demand creation needs the worker
    assert isinstance(t, str) and t.startswith(f"error not_found: no function at or containing 0x{bare:08x}")
    ca = tg.code_address(ctx, "", "main")                                      # what `_create_on_demand` creates
    assert ca is not None and ca[1] == bare


def test_main_x64_entry_function_holds_pascalmain(tmp_path, monkeypatch):
    """FPC 3.0.4 x64 passes no record: the called entry function does ``xor rcx,rcx; lea rdx,[PASCALMAIN]``."""
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "fpc", 8)
    callee = ent + 0x40
    call = b"\x48\x8d\x64\x24\xd8" + b"\xe8" + struct.pack("<i", callee - (ent + 5 + 5)) + b"\xc3"
    body = b"\x55\x48\x89\xe5" + b"\x48\x31\xc9\x48\x8d\x15"
    body += struct.pack("<i", pm - (callee + len(body) + 4)) + b"\xe8" + struct.pack("<i", 0) + b"\xc3"
    code = bytearray(0x1000)
    off = ent - (base + 0x1000)
    code[off:off + len(call)] = call
    code[off + 0x40:off + 0x40 + len(body)] = body
    code[pm - (base + 0x1000)] = 0xC3
    img = cpp.Image(8, base, [cpp.Section(base + 0x1000, bytes(code), True, 0x1000)])
    monkeypatch.setattr(cpp.Image, "from_pe", classmethod(lambda cls, p: img))
    monkeypatch.setattr("airlock.projects.detect", lambda p: _Info(ent - base))
    assert tg.fpc_pascalmain(img, ent) == pm
    t = tg.resolve_target(ctx, "", "main", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == pm
