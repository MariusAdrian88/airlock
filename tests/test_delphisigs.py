"""Delphi signature databases: demangling, masking, bounds, file format, matching (synthetic packages)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from airlock.config.loader import default_config_text, parse_jsonc, resolve
from airlock.server import delphi, delphisigs, idr
from airlock.server.cpp import Image
from test_idr import body, build_kb, make_image, masks, proj, relocated  # noqa: F401  (proj is a fixture)

BASE32 = 0x50000000
BASE64 = 0x180000000
COMPILER = b"Embarcadero Delphi for Win32 compiler version 30.0 (22858)\0"


# ── a synthetic package: .text + export directory + relocations ──────────────

def make_bpl(path: Path, routines: list[tuple[str, bytes]], relocs: list[int] = (), psize: int = 4,
             extra_exports: list[tuple[str, int]] = (), tail: bytes = b"") -> dict[str, int]:
    """Write a PE with ``routines`` (mangled name, code) in .text, 16-byte aligned, one export each.
    ``relocs`` are offsets inside .text of relocated 4/8 byte slots. Returns {name: rva}."""
    text = bytearray()
    where = {}
    for name, code in routines:
        text += b"\xcc" * (-len(text) % 16)
        where[name] = 0x1000 + len(text)
        text += code
    text += b"\xcc" * 16
    names = [(n, where[n]) for n, _c in routines] + list(extra_exports)
    names.sort()
    edata = bytearray(40)
    strs = bytearray()
    n = len(names)
    # layout: dir(40) | functions(4n) | names(4n) | ordinals(2n) | strings
    f_off, n_off, o_off = 40, 40 + 4 * n, 40 + 8 * n
    s_base = 40 + 10 * n
    s_rvas = []
    for nm, _rva in names:
        s_rvas.append(0x2000 + s_base + len(strs))
        strs += nm.encode() + b"\0"
    edata += b"".join(struct.pack("<I", rva) for _n, rva in names)
    edata += b"".join(struct.pack("<I", r) for r in s_rvas)
    edata += b"".join(struct.pack("<H", i) for i in range(n))
    edata += strs
    struct.pack_into("<IIHHIIIIIII", edata, 0, 0, 0, 0, 0, 0x2000 + s_base, 1, n, n,
                     0x2000 + f_off, 0x2000 + n_off, 0x2000 + o_off)
    reloc = bytearray()
    ents = [(0x1000 + r, 3 if psize == 4 else 10) for r in relocs]
    if ents:
        body_ = b"".join(struct.pack("<H", (t << 12) | (rva & 0xFFF)) for rva, t in ents)
        reloc += struct.pack("<II", 0x1000, 8 + len(body_) + (len(body_) % 4)) + body_ + b"\0" * (len(body_) % 4)
    secs = [(b".text", 0x1000, bytes(text), 0x60000020), (b".edata", 0x2000, bytes(edata), 0x40000040),
            (b".reloc", 0x3000, bytes(reloc) or b"\0" * 8, 0x42000040)]
    opt_size = 0xE0 if psize == 4 else 0xF0
    hdr = bytearray(0x200)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x40)
    hdr[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x44, 0x14C if psize == 4 else 0x8664, len(secs), 0, 0, 0, opt_size, 0x2102)
    o = 0x58
    struct.pack_into("<H", hdr, o, 0x10B if psize == 4 else 0x20B)
    base = BASE32 if psize == 4 else BASE64
    if psize == 4:
        struct.pack_into("<IIII", hdr, o + 4, 0, 0, 0, 0)
        struct.pack_into("<I", hdr, o + 28, base)
        dd = o + 96
    else:
        struct.pack_into("<Q", hdr, o + 24, base)
        dd = o + 112
    struct.pack_into("<II", hdr, o + 32, 0x1000, 0x200)             # SectionAlignment, FileAlignment
    struct.pack_into("<II", hdr, o + 56, 0x4000, 0x200)             # SizeOfImage, SizeOfHeaders
    struct.pack_into("<I", hdr, dd - 4, 16)                         # NumberOfRvaAndSizes
    struct.pack_into("<II", hdr, dd, 0x2000, len(edata))            # export directory
    struct.pack_into("<II", hdr, dd + 5 * 8, 0x3000, len(reloc))    # base relocations
    sh = 0x44 + 20 + opt_size
    raw = bytearray(hdr)
    pos = 0x200
    for i, (nm, va, data, ch) in enumerate(secs):
        padded = data + b"\0" * (-len(data) % 0x200)
        struct.pack_into("<8sIIIIIIHHI", hdr, sh + 40 * i, nm, len(data), va, len(padded), pos, 0, 0, 0, 0, ch)
        pos += len(padded)
        raw += padded
    raw[:0x200] = hdr
    path.write_bytes(bytes(raw) + tail)
    return where


def i32(v: int) -> bytes:
    return struct.pack("<i", v)


# 32-bit routine: prologue, a call out of the routine, a relocated global read, an inner short jump.
def routine32(call_rel: int, glob: int) -> tuple[bytes, list[int]]:
    code = (b"\x55\x8b\xec\x83\xc4\xf4\x53\x56\x8b\xd8\x33\xc0"          # push ebp; mov ebp,esp; add esp,-12; ...
            + b"\xe8" + i32(call_rel)                                       # call <outside>        at 12
            + b"\xa1" + struct.pack("<I", glob)                             # mov eax,[abs]         at 17
            + b"\x85\xc0\x74\x01\x40"                                       # test eax,eax; jz +1; inc eax
            + b"\x5e\x5b\x8b\xe5\x5d\xc3")                                  # pop esi; pop ebx; leave; ret
    return code, [18]


def table_routine(call_rel: int, ja_rel_target_gap: int = 0) -> tuple[bytes, list[int], int]:
    """cmp / ja default / jmp [table] with two relocated slots, code after the table."""
    parts = [b"\x53\x8b\xd8\x83\xfb\x01"]                                    # push ebx; mov ebx,eax; cmp ebx,1
    # layout: 0..5 above, ja rel32 at 6..11, jmp [ebx*4+table] at 12..18, table 19..26, L0 27, L1, default
    l0 = b"\x33\xc0\x5b\xc3"                                                 # xor eax,eax; pop ebx; ret
    l1 = b"\xb8\x01\x00\x00\x00\x5b\xc3"
    dflt = b"\x83\xc8\xff\x5b\xc3"
    off_l0, off_l1 = 27, 27 + len(l0)
    off_d = off_l1 + len(l1)
    ja = b"\x0f\x87" + i32(off_d - 12)
    jmp = b"\xff\x24\x9d" + struct.pack("<I", BASE32 + 0x1000 + 19)
    table = struct.pack("<II", BASE32 + 0x1000 + off_l0, BASE32 + 0x1000 + off_l1)
    code = parts[0] + ja + jmp + table + l0 + l1 + dflt
    return code, [15, 19, 23], off_d + len(dflt)


def sweep_one(tmp_path, routines, relocs=(), psize=4):
    capstone = pytest.importorskip("capstone")                              # noqa: F841
    make_bpl(tmp_path / "t.bpl", routines, list(relocs), psize)
    _ps, recs = delphisigs.scan_bpl(str(tmp_path / "t.bpl"))
    return {n: (d, m) for n, d, m in recs}


# ── demangling ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("mangled,want", [
    ("@System@@LStrAsg$qqrrpvpxv", "System.@LStrAsg"),
    ("@System@Classes@TList@Add$qqrpv", "System.Classes.TList.Add"),
    ("@System@Classes@TComponent@$bctr$qqrp14System@TObject", "System.Classes.TComponent.Create"),
    ("@System@Classes@TComponent@$bdtr$qqrv", "System.Classes.TComponent.Destroy"),
    ("@System@Generics@Collections@%TList__1$p25System@Classes@TComponent%@Add$qqrp25System@Classes@TComponent",
     "System.Generics.Collections.TList<T>.Add"),
    ("@System@Generics@Collections@%TDictionary__2$20System@UnicodeStringi%@%TPair__2$i%@Get$qqrv",
     "System.Generics.Collections.TDictionary<T>.TPair<T>.Get"),
    ("@Vcl@Forms@TForm@ShowModal$qqrv", "Vcl.Forms.TForm.ShowModal"),
])
def test_demangle(mangled, want):
    assert delphisigs.demangle(mangled) == want


@pytest.mark.parametrize("mangled", ["@$xp$18System@PackageInfo", "@System@Classes@TComponent@", "NotMangled",
                                     "@System@Sysconst@_SLongMonthNameJul", "@", "@@$qqrv"])
def test_demangle_rejects_non_routines(mangled):
    assert delphisigs.demangle(mangled) is None


# ── masking and bounds ───────────────────────────────────────────────────────

def test_masks_call_operand_and_relocations(tmp_path):
    code, rel = routine32(0x12345, BASE32 + 0x5000)
    out = sweep_one(tmp_path, [("@Unit@Func$qqrv", code)], rel)
    dump, mask = out["Unit.Func"]
    assert len(dump) == len(code)                                           # ends at the ret, not at padding
    masked = {i for i, m in enumerate(mask) if m}
    assert masked == set(range(13, 17)) | set(range(18, 22))               # call rel32, relocated global
    assert all(dump[i] == 0 for i in masked)                               # masked bytes are zeroed
    assert dump[:13] == code[:13] and dump[22:] == code[22:]


def test_inner_branches_stay_and_jump_table_is_followed(tmp_path):
    code, rel, total = table_routine(0)
    out = sweep_one(tmp_path, [("@Unit@Switch$qqri", code), ("@Unit@Next$qqrv", routine32(0, BASE32)[0])], rel)
    dump, mask = out["Unit.Switch"]
    assert len(dump) == total == len(code)                                  # code after the table is included
    masked = {i for i, m in enumerate(mask) if m}
    assert masked == {15, 16, 17, 18} | set(range(19, 27))                 # table operand and both slots; ja rel32 is inner
    assert dump[6:8] == b"\x0f\x87" and dump[8:12] == code[8:12]


def test_tail_jump_ends_the_routine_and_is_masked(tmp_path):
    code = b"\x8b\x10\x83\xc2\x04\x89\x10\x8b\xc2\xe9" + i32(0x4000)         # ... jmp <outside>
    out = sweep_one(tmp_path, [("@Unit@Tail$qqrv", code + b"\x90\x90\x90")])
    dump, mask = out["Unit.Tail"]
    assert len(dump) == len(code) and [i for i, m in enumerate(mask) if m] == [10, 11, 12, 13]


def test_routine_without_terminator_is_cut_at_the_next_export(tmp_path):
    a = b"\x8b\x10\x83\xc2\x04\x89\x10\x8b\xc2\x40\x40\x40\x40\x40\x40\x40"    # runs into the next routine
    out = sweep_one(tmp_path, [("@Unit@A$qqrv", a), ("@Unit@B$qqrv", routine32(0, BASE32)[0])], [])
    assert len(out["Unit.A"][0]) == len(a)


def test_sixty_four_bit_masks_rip_relative_and_qwords(tmp_path):
    mov_out = b"\x48\x8b\x05" + i32(0x2000)                                 # mov rax,[rip+0x2000]  (outside)
    lea_in = b"\x48\x8d\x15" + i32(3)                                       # lea rdx,[rip+3] -> inside
    movabs = b"\x48\xb8" + struct.pack("<Q", BASE64 + 0x5000)               # movabs rax,<reloc>
    code = (b"\x48\x83\xec\x28" + mov_out + lea_in + b"\x90\x90\x90" + movabs
            + b"\xe8" + i32(0x300) + b"\x48\x83\xc4\x28\xc3")
    rel = [23]
    out = sweep_one(tmp_path, [("@Unit@Wide$qqrv", code)], rel, psize=8)
    dump, mask = out["Unit.Wide"]
    masked = {i for i, m in enumerate(mask) if m}
    want = set(range(7, 11)) | set(range(23, 31)) | set(range(32, 36))        # rip disp, qword, call rel32
    assert masked == want and len(dump) == len(code)


# ── file format and loading ──────────────────────────────────────────────────

def test_database_roundtrip_and_files(tmp_path):
    raw = body(1)
    recs = [("System.@Foo", raw, masks(len(raw))), ("System.Classes.TList.Add", body(2), masks(len(raw)))]
    delphisigs.write_sigdb(tmp_path / "30-32.sigdb", 30, 4, recs, {"install": "x"})
    delphisigs.write_sigdb(tmp_path / "30-64.sigdb", 30, 8, recs)
    (tmp_path / "junk.sigdb").write_bytes(b"x" * 100)
    assert [f.label for f in idr.sig_files(tmp_path, 4)] == ["sig30-32"]
    assert [f.label for f in idr.sig_files(tmp_path, 8)] == ["sig30-64"]
    assert idr.sig_files(None, 4) == [] and idr.sig_files(tmp_path / "none", 4) == []
    kb = delphisigs.read_sigdb(tmp_path / "30-32.sigdb")
    assert [p.name for p in kb.procs] == ["System.@Foo", "System.Classes.TList.Add"]
    assert delphisigs.read_sigdb_header(tmp_path / "30-32.sigdb")["install"] == "x"
    with pytest.raises(idr.KbError):
        delphisigs.read_sigdb(tmp_path / "junk.sigdb")
    (tmp_path / "30-32.sigdb").write_bytes((tmp_path / "30-32.sigdb").read_bytes()[:-20])
    with pytest.raises(idr.KbError):
        delphisigs.read_sigdb(tmp_path / "30-32.sigdb")


# ── matching a statically linked copy ────────────────────────────────────────

def test_static_copy_is_named_by_the_package_signature(tmp_path):
    pytest.importorskip("capstone")
    code, rel = routine32(0x111, BASE32 + 0x5000)
    other, rel2 = routine32(0x222, BASE32 + 0x5100)
    other = other[:-1] + b"\x90\xc3"                                        # differs in an unmasked byte
    make_bpl(tmp_path / "rtl230.bpl", [("@System@Classes@TThing@Run$qqrv", code)], rel, tail=COMPILER)
    sigdir = tmp_path / "sig"
    res = delphisigs.build(_install(tmp_path), sigdir, 4, jobs=1)
    assert res.compiler == 30 and res.path.name == "30-32.sigdb" and res.names == 1
    exe, _r = routine32(0x7777, 0x405000)                                    # different call target and global
    path, at = make_image(tmp_path, {"same": exe, "other": other}, data=COMPILER)
    img = Image.from_pe(path)
    kb = delphisigs.read_sigdb(res.path)
    got = idr.match_all(kb, img, [(at["same"], len(code)), (at["other"], len(other))])
    assert got == {at["same"]: ["System.Classes.TThing.Run"]}


def _install(tmp_path: Path) -> Path:
    inst = tmp_path / "inst"
    (inst / "Redist" / "win32").mkdir(parents=True, exist_ok=True)
    (tmp_path / "rtl230.bpl").replace(inst / "Redist" / "win32" / "rtl230.bpl")
    return inst


def test_build_without_packages_fails(tmp_path):
    with pytest.raises(delphisigs.SigError):
        delphisigs.build(tmp_path, tmp_path / "out", 8)


def test_exact_signature_wins_and_knowledge_base_fills_the_rest(tmp_path):
    a, b, c = body(50), body(51), body(52)
    sig = tmp_path / "sig"
    sig.mkdir()
    delphisigs.write_sigdb(sig / "30-32.sigdb", 30, 4, [("System.Sig.A", a, masks(len(a)))])
    kb = tmp_path / "kb"
    kb.mkdir()
    build_kb(kb / "kb2014.bin", ["System"], [(0, "OtherA", a, masks(len(a))), (0, "OnlyB", b, masks(len(b)))])
    path, at = make_image(tmp_path, {"a": relocated(a, 1, 2), "b": relocated(b, 3, 4), "c": relocated(c, 5, 6)}, data=COMPILER)
    img = Image.from_pe(path)
    files = idr.kb_files(kb, 4, sig)
    assert [f.label for f in files] == ["kb2014", "sig30-32"]
    label, hits, notes = idr._pick(files, img, [(va, None) for va in at.values()])
    assert hits[at["a"]] == ["System.Sig.A"]                                # the signature database goes first
    assert hits[at["b"]] == ["System.OnlyB"] and label.startswith("sig30-32+")
    assert notes[0] == "sig30-32 1/3"
    # no compiler string: the signature database of another version competes with the knowledge bases
    delphisigs.write_sigdb(sig / "29-32.sigdb", 29, 4, [("System.Old.C", c, masks(len(c)))])
    path, at = make_image(tmp_path, {"c": relocated(c, 5, 6)})
    label, hits, notes = idr._pick(idr.kb_files(None, 4, sig), Image.from_pe(path), [(at["c"], None)])
    assert label == "sig29-32" and hits == {at["c"]: ["System.Old.C"]}


def test_ensure_uses_signatures_without_knowledge_bases(proj, tmp_path):  # noqa: F811
    ctx, st, bid, art, kbdir, base = proj
    b = st.get_binary_by_id(bid)
    raw = body(20)
    sig = tmp_path / "sigs"
    sig.mkdir()
    delphisigs.write_sigdb(sig / "30-32.sigdb", 30, 4, [("System.Sig.Thing", raw, masks(len(raw)))])
    assert idr.stale(st, b, None, sig) and idr.ensure(st, b, art, None, sig)
    assert st.get_meta(f"idr_version:{bid}").startswith(f"{idr.IDR_VERSION}:") and not idr.stale(st, b, None, sig)
    assert idr.hits(st, bid) == {base: "System.Sig.Thing"}
    assert idr.info(st, bid).startswith("sig30-32: 1 of 2 unnamed functions named")
    assert base in delphi.runtime_addrs(st, bid)
    (sig / "30-32.sigdb").unlink()                                          # database removed: result cleared
    assert idr.stale(st, b, None, sig) and idr.ensure(st, b, art, None, sig) and idr.hits(st, bid) == {}


# ── configuration and command ────────────────────────────────────────────────

def test_config_key_default_and_override(tmp_path):
    cfg = resolve(parse_jsonc(default_config_text()), "dirty", None)
    assert cfg.delphi_sigdb_dir == cfg.data_dir / "sigdb"
    merged = parse_jsonc(default_config_text())
    merged["delphi_sigdb_dir"] = str(tmp_path / "s")
    merged["ghidra_dir"] = str(tmp_path / "g")
    assert resolve(merged, "dirty", None).delphi_sigdb_dir == tmp_path / "s"


def test_command_builds_and_lists(tmp_path, capsys):
    pytest.importorskip("capstone")
    from airlock.cli import main
    code, rel = routine32(0x111, BASE32 + 0x5000)
    make_bpl(tmp_path / "rtl230.bpl", [("@System@Classes@TThing@Run$qqrv", code)], rel, tail=COMPILER)
    inst = _install(tmp_path)
    cfg = tmp_path / "config.jsonc"
    cfg.write_text('{"ghidra_dir": "%s"}' % str(tmp_path).replace("\\", "/"))
    out = tmp_path / "out"
    assert main(["--config", str(cfg), "delphi-sigs", "build", str(inst), "--out", str(out), "--jobs", "1"]) == 0
    text = capsys.readouterr().out
    assert "compiler 30, 32-bit, 1 packages, 1 names" in text and "64-bit: no .bpl packages" in text
    assert (out / "30-32.sigdb").is_file()
    assert main(["--config", str(cfg), "delphi-sigs", "list", "--out", str(out)]) == 0
    assert "30-32.sigdb: compiler 30, 32-bit, 1 names" in capsys.readouterr().out
