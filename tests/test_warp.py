"""WARP reader and GUID rules with synthetic data (no Binary Ninja, no Ghidra, no network)."""

from __future__ import annotations

import struct
import uuid
import zlib

import pytest

from airlock.server import warp


class _FB:
    """Tiny FlatBuffers writer: tables first-parent, offsets patched at the end."""

    def __init__(self) -> None:
        self.buf = bytearray(4)  # root offset
        self.patches: list[tuple[int, int]] = []  # (field position, target position)

    def table(self, fields: list[tuple[int, str, object]]) -> int:
        """fields: (index, kind, value); kind u8/u16/u32/i64/raw (inline bytes)/ref (position of another object)."""
        sizes = {"u8": 1, "u16": 2, "u32": 4, "i64": 8}
        nfields = max(i for i, _, _ in fields) + 1
        vt_pos = len(self.buf)
        self.buf += bytes(4 + 2 * nfields)
        t_pos = len(self.buf)
        struct.pack_into("<HH", self.buf, vt_pos, 4 + 2 * nfields, 0)
        self.buf += struct.pack("<i", t_pos - vt_pos)
        off = 4
        for idx, kind, val in fields:
            struct.pack_into("<H", self.buf, vt_pos + 4 + 2 * idx, off)
            if kind == "ref":
                if val:
                    self.patches.append((t_pos + off, int(val)))  # type: ignore[arg-type]
                self.buf += bytes(4)
                off += 4
            elif kind == "raw":
                self.buf += val  # type: ignore[operator]
                off += len(val)  # type: ignore[arg-type]
            else:
                fmt = {"u8": "<B", "u16": "<H", "u32": "<I", "i64": "<q"}[kind]
                self.buf += struct.pack(fmt, val)
                off += sizes[kind]
        struct.pack_into("<H", self.buf, vt_pos + 2, off)
        return t_pos

    def string(self, s: str) -> int:
        pos = len(self.buf)
        raw = s.encode()
        self.buf += struct.pack("<I", len(raw)) + raw + b"\0"
        return pos

    def vec(self, kind: str, items: list) -> int:
        pos = len(self.buf)
        self.buf += struct.pack("<I", len(items))
        if kind == "bytes":
            self.buf += bytes(items)
            return pos
        for t in items:
            self.patches.append((len(self.buf), t))
            self.buf += bytes(4)
        return pos

    def finish(self, root: int) -> bytes:
        for at, target in self.patches:
            struct.pack_into("<I", self.buf, at, target - at)
        struct.pack_into("<I", self.buf, 0, root)
        return bytes(self.buf)


def make_warp(funcs: list[tuple[bytes, str, list[tuple[bytes, int]]]], compress: bool = True) -> bytes:
    """A `.warp` file with one signature chunk holding `funcs` (guid, name, constraints)."""
    sc = _FB()
    # parents first so every offset points forward
    root = sc.table([(0, "ref", 0)])
    vec_pos = len(sc.buf)
    sc.buf += struct.pack("<I", len(funcs)) + bytes(4 * len(funcs))
    sc.patches.append((root + 4, vec_pos))
    for i, (guid, name, cons) in enumerate(funcs):
        refs_idx = 4 * i + vec_pos + 4
        fpos = sc.table([(0, "raw", guid), (1, "ref", 0), (3, "ref", 0)])
        sc.patches.append((refs_idx, fpos))
        sym = sc.table([(0, "ref", 0)])
        sname = sc.string(name)
        sc.patches.append((sym + 4, sname))
        sc.patches.append((fpos + 4 + 16, sym))
        cons_vec = len(sc.buf)
        sc.buf += struct.pack("<I", len(cons)) + bytes(4 * len(cons))
        sc.patches.append((fpos + 4 + 16 + 4, cons_vec))
        for j, (cg, co) in enumerate(cons):
            cpos = sc.table([(0, "raw", cg), (1, "i64", co)])
            sc.patches.append((cons_vec + 4 + 4 * j, cpos))
    chunk = sc.finish(root)
    if compress:
        chunk = zlib.compress(chunk)
    fb = _FB()
    file_root = fb.table([(0, "ref", 0), (1, "ref", 0)])
    hdr = fb.table([(0, "u16", 1)])
    fb.patches.append((file_root + 4, hdr))
    chunks_vec = len(fb.buf)
    fb.buf += struct.pack("<I", 1) + bytes(4)
    fb.patches.append((file_root + 8, chunks_vec))
    ch = fb.table([(0, "ref", 0), (1, "ref", 0)])
    fb.patches.append((chunks_vec + 4, ch))
    ch_hdr = fb.table([(0, "u16", 1), (1, "u8", 0), (2, "u8", 1 if compress else 0), (3, "u32", len(chunk))])
    fb.patches.append((ch + 4, ch_hdr))
    data_vec = fb.vec("bytes", list(chunk))
    fb.patches.append((ch + 8, data_vec))
    return fb.finish(file_root)


def test_readme_function_guid_vector():
    bbs = [uuid.UUID(x).bytes for x in ("036cccf0-8239-5b84-a811-60efc2d7eeb0",
                                        "3ed5c023-658d-5511-9710-40814f31af50",
                                        "8a076c92-0ba0-540d-b724-7fd5838da9df")]
    assert uuid.UUID(bytes=warp.function_guid(bbs)) == uuid.UUID("7a55be03-76b7-5cb5-bae9-4edcf47795ac")


@pytest.mark.parametrize("compress", [True, False])
def test_read_synthetic_file(compress):
    g1, g2 = warp.block_guid(b"\x90\x90"), warp.block_guid(b"\xc3")
    c1 = warp.uuid5(warp.CONSTRAINT_NS, b"x")
    data = make_warp([(g1, "System::TObject::Free", [(c1, 12)]), (g2, "System::_Halt", []),
                      (g1, "Other::Same", [])], compress)
    lib = warp.read_warp(data, with_constraints=True)
    assert len(lib) == 3
    assert [f.name for f in lib.functions[g1]] == ["System::TObject::Free", "Other::Same"]
    assert lib.functions[g1][0].constraints == ((c1, 12),)
    assert lib.functions[g2][0].name == "System::_Halt"
    assert warp.read_warp(data).functions[g1][0].constraints == ()


def test_bad_file_is_an_error():
    with pytest.raises(warp.WarpError):
        warp.read_warp(b"abc")
    with pytest.raises(warp.WarpError):
        warp.read_warp(bytes([255]) * 64)


def test_masking_rules():
    F = warp
    # mov eax,[abs] (variant), nop (dropped), jcc with in-region target (kept), ret (kept)
    raw = bytes.fromhex("a100104000" "90" "7405" "c3")
    meta = [5, F.F_CONST, 1, F.F_NOP, 2, F.F_CONST | F.F_JCC, 1, F.F_RET]
    assert F.block_bytes(raw, meta) == bytes(5) + bytes.fromhex("7405c3")
    # unconditional jump inside the function is kept, one leaving it is masked, a call is masked
    assert F.block_bytes(b"\xeb\x05", [2, F.F_CONST | F.F_JMP]) == b"\xeb\x05"
    assert F.block_bytes(b"\xeb\x05", [2, F.F_CONST | F.F_JMP | F.F_OUT]) == bytes(2)
    assert F.block_bytes(b"\xe8\x01\x02\x03\x04", [5, F.F_CONST | F.F_CALL]) == bytes(5)


def test_guid_from_blocks_orders_by_address_and_ignores_masked_operands():
    a = [0x10, "a100104000c3", [5, warp.F_CONST, 1, warp.F_RET]]
    b = [0x20, "90c3", [1, warp.F_NOP, 1, warp.F_RET]]
    a2 = [0x10, "a100204000c3", [5, warp.F_CONST, 1, warp.F_RET]]  # other address operand
    assert warp.guid_from_blocks([b, a]) == warp.guid_from_blocks([a2, b])
    assert warp.guid_from_blocks([a]) != warp.guid_from_blocks([a, b])
    assert warp.guid_from_blocks([]) is None


# ---- libraries by compiler, blocks from an image, the tier in idr._pick ---------------------------

def _image(call_rel: int, abs_addr: int, tail: bytes = b""):
    from airlock.server.cpp import Image, Section
    code = (b"\x53\x89\xc3" + b"\xe8" + call_rel.to_bytes(4, "little", signed=True)
            + b"\xa1" + abs_addr.to_bytes(4, "little") + b"\xb9\x05\x00\x00\x00\x5b\xc3")
    code += b"\x90" * (32 - len(code))
    stamp = b"Embarcadero Delphi for Win32 compiler version 35.0 (x)\0"
    return Image(4, 0x400000, [Section(0x401000, code + tail, True, 0x1000),
                               Section(0x403000, stamp + bytes(0x100), False, 0x1000)])


def test_library_stems():
    assert warp.library_stems(35) == ["core-11"]
    assert warp.library_stems(34) == ["10.4-only", "core-11"]
    assert warp.library_stems(30) == ["core-11", "xe2plus-only"]
    assert warp.library_stems(20) == ["2009-only", "core-8"]
    assert warp.library_stems(None) == []


def test_image_guid_ignores_relocatable_operands_and_matches():
    a, b = _image(0x100, 0x403010), _image(0x200, 0x403020)
    regions = warp.image_regions(a)
    ga = warp.guid_from_blocks(warp.image_blocks(a, 0x401000, 32, regions))
    gb = warp.guid_from_blocks(warp.image_blocks(b, 0x401000, 32, warp.image_regions(b)))
    assert ga == gb
    lib = warp.read_warp(make_warp([(ga, "System::Demo", [])]))
    assert warp.match_functions(lib, b, [(0x401000, 32), (0x401000, 8)]) == {0x401000: ["System.Demo"]}
    assert warp.match_functions(lib, _image(0, 0x403000, b""), [(0x401001, 31)]) == {}


def test_warp_tier_in_pick_and_stale_signature(tmp_path):
    from airlock.server import idr
    img = _image(0x100, 0x403010)
    g = warp.guid_from_blocks(warp.image_blocks(img, 0x401000, 32, warp.image_regions(img)))
    wd = tmp_path / "w"
    wd.mkdir()
    (wd / "delphi-rtl-core-11.warp").write_bytes(make_warp([(g, "System::Demo", [])]))
    (wd / "delphi-rtl-core-8.warp").write_bytes(make_warp([(g, "Wrong::Old", [])]))   # not for compiler 35
    (wd / "notes.txt").write_text("x" * 100)
    files = idr.kb_files(None, 4, None, wd)
    assert [f.label for f in files] == ["warp-core-11", "warp-core-8"] and all(f.warp for f in files)
    assert idr.kb_files(None, 8, None, wd) == []                      # 32-bit only
    label, hits, notes = idr._pick(files, img, [(0x401000, 32)])
    assert label == "warp" and hits == {0x401000: ["System.Demo"]}, notes
    assert idr.kb_signature(files) != idr.kb_signature(files[:1])
    # a name from an earlier database wins: nothing here, so an unreadable file only adds a note
    (wd / "delphi-rtl-core-11.warp").write_bytes(b"\xff" * 100)
    label, hits, notes = idr._pick(idr.kb_files(None, 4, None, wd), img, [(0x401000, 32)])
    assert hits == {} and any(n.startswith("warp:") for n in notes)


def test_warp_dir_config_key(tmp_path):
    from airlock.config.loader import default_config_text, parse_jsonc, resolve
    cfg = resolve(parse_jsonc(default_config_text()), "dirty", None)
    assert cfg.warp_dir == cfg.data_dir / "warp"
    merged = parse_jsonc(default_config_text())
    merged["warp_dir"] = str(tmp_path / "w")
    merged["ghidra_dir"] = str(tmp_path / "g")
    assert resolve(merged, "dirty", None).warp_dir == tmp_path / "w"


def test_dotted_names_follow_the_other_tiers():
    d = warp.dotted
    assert d("System::TObject::Free") == "System.TObject.Free"
    assert d("System::@GetAnsiChar") == "System.@GetAnsiChar"
    assert d("SysUtils::Exception::Create") == "System.SysUtils.Exception.Create"
    assert d("Types::EqualRect") == "System.Types.EqualRect"
    assert d("Graphics::TCanvas::Create") == "Vcl.Graphics.TCanvas.Create"
    assert d("Windows::GetTickCount") == "Winapi.Windows.GetTickCount"
    assert d("System.Classes::TList::Add") == "System.Classes.TList.Add"       # already has its namespace
    assert d("SysInit::_DF_") == "SysInit._DF_."
    assert d("MyUnit::Foo") == "MyUnit.Foo"


def test_idr_file_is_chosen_without_the_functions_warp_names(tmp_path):
    from airlock.server import idr
    seen = {}
    real = idr._pick_idr

    def spy(files, img, funcs, comp, score=None):
        seen["funcs"], seen["score"] = list(funcs), list(score or [])
        return real(files, img, funcs, comp, score)

    img = _image(0x100, 0x403010)
    g = warp.guid_from_blocks(warp.image_blocks(img, 0x401000, 32, warp.image_regions(img)))
    wd = tmp_path / "w"
    wd.mkdir()
    (wd / "delphi-rtl-core-11.warp").write_bytes(make_warp([(g, "System::Demo", [])]))
    kb = tmp_path / "kb2014.bin"
    kb.write_bytes(b"x" * 500)
    files = idr.kb_files(tmp_path, 4, None, wd)
    mp = pytest.MonkeyPatch()
    mp.setattr(idr, "_pick_idr", spy)
    try:
        idr._pick(files, img, [(0x401000, 32), (0x401010, 16)])
    finally:
        mp.undo()
    assert seen["funcs"] == [(0x401010, 16)] and seen["score"] == [(0x401000, 32), (0x401010, 16)]
