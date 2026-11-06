"""Delphi string literal detection (worker/ghidra_ops/delphistr.py, pure part)."""

from __future__ import annotations

import struct

from airlock.worker.ghidra_ops import delphistr as D


def strrec(text: str, elem: int = 2, cp: int = 1200, x64: bool = False, ref: int = -1) -> bytes:
    """A Delphi 2009+ string literal: [x64 padding] codePage, elemSize, refCnt, length, chars, 0."""
    raw = text.encode("utf-16-le" if elem == 2 else "latin-1")
    head = (b"\xcc" * 4 if x64 else b"") + struct.pack("<HHii", cp, elem, ref, len(text))
    return head + raw + b"\0" * elem


def test_unicode_literals_32_and_64_bit():
    for x64 in (False, True):
        lead = b"\x90" * 7
        buf = lead + strrec("TABLES WITH READ LOCK", x64=x64) + strrec("<|||>", x64=x64) + b"\xc3"
        got = list(D.scan_strrec(buf, 0x1000))
        first = 0x1000 + len(lead) + (16 if x64 else 12)
        assert [(a, k, t) for a, k, _n, t in got] == [
            (first, "u", "TABLES WITH READ LOCK"),
            (first + 21 * 2 + 2 + (16 if x64 else 12), "u", "<|||>")]
        assert got[0][2] == 22 * 2          # characters and the terminator


def test_ansi_literal_and_rejects():
    buf = strrec("Hello, world", elem=1, cp=65001)
    assert [(k, t) for _a, k, _n, t in D.scan_strrec(buf)] == [("a", "Hello, world")]
    assert not list(D.scan_strrec(strrec("abc", cp=1252)))            # elemSize 2 needs code page 1200
    assert not list(D.scan_strrec(strrec("abc", ref=1)))              # a heap string, not a literal
    assert not list(D.scan_strrec(strrec("abc")[:-2] + b"x\0"))      # no terminator
    assert not list(D.scan_strrec(strrec("a\x01c")))                  # control characters
    assert not list(D.scan_strrec(strrec("abc")[:14]))                # cut off by the block end
    assert list(D.scan_strrec(strrec("line\r\n")))                     # CR/LF/TAB are text


def test_shortstring():
    buf = b"\x00" + bytes([8]) + b"Segoe UI" + b"\x00"
    assert D.shortstring_at(buf, 1) == "Segoe UI"
    assert D.shortstring_at(bytes([5]) + b"Hello", 0) is None        # an identifier: RTTI name
    assert D.shortstring_at(bytes([2]) + b"ab", 0) is None           # too short to trust
    # type info: kind byte 17 (tkDynArray), then a ShortString name of 32 characters
    name = b"TArray<System.SysUtils.TBytes3>a"
    assert len(name) == 32
    assert D.shortstring_at(bytes([17, 32]) + name + b"\0" * 8, 0) is None
    assert D.shortstring_at(bytes([4]) + b"err\x07", 0) is None
