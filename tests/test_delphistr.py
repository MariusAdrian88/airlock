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


def oldrec(text: str) -> bytes:
    """A Delphi 2007 AnsiString literal: refCnt -1, length, chars, 0, padded to 4 bytes."""
    raw = struct.pack("<ii", -1, len(text)) + text.encode("latin-1") + b"\0"
    return raw + b"\0" * (-len(raw) % 4)


def widerec(text: str) -> bytes:
    """A WideString literal: byte length, UTF-16 chars, 0, padded to 4 bytes."""
    raw = struct.pack("<I", len(text) * 2) + text.encode("utf-16-le") + b"\0\0"
    return raw + b"\0" * (-len(raw) % 4)


def test_old_ansi_and_wide_literals():
    buf = b"\x8b\xc0\x90\x90" + oldrec("Software\\Tiles") + widerec("[%s]") + oldrec("True")
    got = [(a - 0x1000, k, n, t) for a, k, n, t in D.scan_old(buf, 0x1000)]
    assert got == [(12, "a", 15, "Software\\Tiles"), (52, "a", 5, "True"), (32, "u", 10, "[%s]")]
    assert not list(D.scan_old(b"\x90" + oldrec("Software"), 0x1000))       # header not 4-byte aligned
    assert [t for _a, _k, _n, t in D.scan_old(b"\x90\x90\x90\xff" + oldrec("Software"))] == ["Software"]
    assert [(k, len(t)) for _a, k, _n, t in D.scan_old(widerec("x" * 128))] == [("u", 128)]  # length 0x100
    assert not list(D.scan_old(oldrec("ab\x01c")))                           # control characters
    assert not list(D.scan_old(oldrec("abcd")[:-4] + b"x"))                 # no terminator
    assert not list(D.scan_old(struct.pack("<ii", -1, 0) + b"\0" * 4))      # empty
    assert not list(D.scan_old(widerec("abc")[:4] + b"a\0b\0c\0d\0"))      # no wide terminator
    assert not list(D.scan_old(struct.pack("<I", 5) + b"a\0b\0c\0\0\0"))   # odd byte length
    # ASCII text read as UTF-16 (length 4, then "Tr" "ue"): not a WideString
    assert not [x for x in D.scan_old(struct.pack("<I", 4) + b"True\0\0\0\0") if x[1] == "u"]


def test_delphi_marker():
    assert D.delphi_marker(b"..Software\\Borland\\Locales\0")
    assert D.delphi_marker("Software\\Embarcadero\\Locales".encode("utf-16-le"))
    assert D.delphi_marker(b"SOFTWARE\\Borland\\Delphi\\RTL")
    assert not D.delphi_marker(b"Software\\Microsoft\\Windows")


I = D.Ins


def test_literal_use_register_and_stack_arguments():
    # x64: LEA RDX,[lit] ... CALL
    assert D.literal_use([I("LEA", dst="RDX"), I("MOV", dst="RCX", writes=frozenset({"RCX"})),
                          I("CALL", call=True)], 8) == ("reg", "RDX", 2)
    # x64: LEA RAX,[lit]; MOV [RSP+0x28],RAX; ...; CALL -> fifth/sixth argument at 0x30 in the callee
    seq = [I("LEA", dst="RAX"), I("MOV", mem=("RSP", 0x28), src="RAX"),
           I("MOV", dst="RAX", writes=frozenset({"RAX"})), I("MOV", mem=("RSP", 0x30), src="RAX"),
           I("CALL", call=True)]
    assert D.literal_use(seq, 8) == ("stack", 0x30, 4)
    # x86: PUSH lit; PUSH x; PUSH y; MOV EAX,..; CALL -> two pushes after it: offset 4 + 8
    esp = frozenset({"ESP"})
    seq = [I("PUSH", imm=0x40e1c0, writes=esp), I("PUSH", mem=("EBP", -8), writes=esp),
           I("PUSH", src="EBX", writes=esp), I("MOV", dst="EAX", writes=frozenset({"EAX"})), I("CALL", call=True)]
    assert D.literal_use(seq, 4) == ("stack", 12, 4)
    # x86: MOV EAX,lit; PUSH EAX; CALL
    assert D.literal_use([I("MOV", dst="EAX"), I("PUSH", src="EAX", writes=esp), I("CALL", call=True)], 4) \
        == ("stack", 4, 2)


def test_literal_use_rejects():
    w = frozenset({"RDX"})
    assert D.literal_use([I("LEA", dst="RDX"), I("MOV", dst="RDX", writes=w), I("CALL", call=True)], 8) is None
    assert D.literal_use([I("LEA", dst="RDX"), I("JZ", jump=True), I("CALL", call=True)], 8) is None
    assert D.literal_use([I("MOV", mem=("EBX", 4)), I("CALL", call=True)], 4) is None     # a field store
    esp = frozenset({"ESP"})
    assert D.literal_use([I("PUSH", imm=1, writes=esp), I("POP", dst="ECX", writes=esp | {"ECX"}),
                          I("CALL", call=True)], 4) is None
    assert D.literal_use([I("LEA", dst="RAX")], 8) is None                                  # no call


def test_concat_sites():
    esp = frozenset({"ESP"})
    # x86: PUSH a; PUSH 'lit'; LEA EDX,..; MOV EAX,..; CALL IntToStr(1 stack arg, pushed); PUSH tmp;
    #      LEA EAX,dest; MOV EDX,3; CALL UStrCatN  (nearest first below)
    before = [I("MOV", dst="EDX", imm=3, writes=frozenset({"EDX"})), I("LEA", dst="EAX", writes=frozenset({"EAX"})),
              I("PUSH", mem=("EBP", -12), writes=esp), I("CALL", call=True, pops=1),
              I("PUSH", imm=7, writes=esp), I("MOV", dst="EAX", writes=frozenset({"EAX"})),
              I("PUSH", imm=0x4164dc, writes=esp), I("PUSH", mem=("EBP", -4), writes=esp), I("PUSH", imm=9, writes=esp)]
    assert D.concat_site(before, 4) == (3, 3, [2, 6, 7])
    # x64: count 4, pieces in R8, R9, [RSP+0x20], [RSP+0x28]
    before = [I("MOV", mem=("RSP", 0x28), src="RAX"), I("LEA", dst="RAX", writes=frozenset({"RAX"})),
              I("MOV", mem=("RSP", 0x20), src="RAX"), I("LEA", dst="R9", writes=frozenset({"R9"})),
              I("MOV", dst="R8", writes=frozenset({"R8"})), I("MOV", dst="RDX", imm=4, writes=frozenset({"RDX"})),
              I("LEA", dst="RCX", writes=frozenset({"RCX"})), I("CALL", call=True)]
    assert D.concat_site(before, 8)[:2] == (4, 4)
    assert D.concat_site([I("MOV", dst="RDX", src="RAX", writes=frozenset({"RDX"}))], 8) == (None, 0, [])
    assert D.is_concat([(3, 3), (4, 4), (5, 5), (3, 3), (None, 0)])
    assert not D.is_concat([(3, 3), (4, 4)])                         # too few calls
    assert not D.is_concat([(3, 3), (4, 4), (5, 5), (3, 1), (None, 0)])    # under 80%
    assert D.concat_comment([None, ("u", 'exiftool -@ "'), None, ("a", "\r\n")]) == \
        'concat ? + L"exiftool -@ \\"" + ? + "\\r\\n"'


def test_piece_storage():
    # x86: the first pushed piece sits highest, the last one right above the return address
    assert [D.piece_storage(4, i, 3) for i in range(3)] == [("stack", 12), ("stack", 8), ("stack", 4)]
    # x64: R8, R9, then stack slots behind return address and shadow space
    assert [D.piece_storage(8, i, 5) for i in range(5)] ==         [("reg", "R8"), ("reg", "R9"), ("stack", 0x28), ("stack", 0x30), ("stack", 0x38)]


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


def fpcrec64(text: str, elem: int = 1, cp: int = 0, ref: int = -1) -> bytes:
    """A Free Pascal x64 string literal: codePage, elemSize, u32 padding, i64 refCount, i64 length, chars, 0."""
    raw = text.encode("utf-16-le" if elem == 2 else "latin-1")
    return struct.pack("<HHIqq", cp, elem, 0, ref, len(text)) + raw + b"\0" * elem


def test_fpc_x64_literals():
    lead = b"\x90" * 5
    buf = lead + fpcrec64("Animal: ") + fpcrec64("Wide text", elem=2, cp=1200) + b"\xc3"
    got = list(D.scan_strrec64(buf, 0x2000))
    first = 0x2000 + len(lead) + 24
    assert [(a, k, t) for a, k, _n, t in got] == [
        (first, "a", "Animal: "),
        (first + 9 + 24, "u", "Wide text")]
    assert got[1][2] == 10 * 2
    assert not list(D.scan_strrec(buf))                               # the 12-byte header does not match
    assert not list(D.scan_strrec64(fpcrec64("abc", ref=1)))          # a heap string
    assert not list(D.scan_strrec64(fpcrec64("abc", elem=2, cp=1252)))
    assert not list(D.scan_strrec64(fpcrec64("abc")[:-1] + b"x"))   # no terminator
    assert not list(D.scan_strrec64(fpcrec64("abc")[:26]))            # cut off by the block end
    assert not list(D.scan_strrec64(strrec("abc", x64=True)))         # the Delphi layout is not FPC's


def test_fpc_x86_literals_use_the_delphi_header():
    buf = strrec("Animal: ", elem=1, cp=0) + strrec("Unicode", elem=2, cp=1200)
    assert [t for _a, _k, _n, t in D.scan_strrec(buf)] == ["Animal: ", "Unicode"]
