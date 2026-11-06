"""Free Pascal RTL / LCL signature databases (``fpcsigs``): symbol names, the scan of a program that keeps its
COFF symbols, the database file, how ``idr`` applies it to ``fpc`` binaries, the virtual slot and interface
names. Synthetic data only (invented names, hand written x86 bytes). No Ghidra, no FPC install."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from airlock.server import delphi, delphisigs, fpcsigs, idr
from airlock.server.cpp import Image
from test_delphi import Pe
from test_delphisigs import make_bpl
from test_idr import MASK


# ── names ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sym, want", [
    ("CLASSES$_$TLIST_$__$$_ADD$POINTER$$LONGINT", "CLASSES.TLIST.ADD"),
    ("SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING", "SYSUTILS.INTTOSTR"),
    ("SYSTEM$_$TOBJECT_$__$$_CREATE$$TOBJECT", "SYSTEM.TOBJECT.CREATE"),
    ("P$T1$_$TDOG_$__$$_SPEAK$$ANSISTRING", "T1.TDOG.SPEAK"),
    ("P$T1_$$_HELPER", "T1.HELPER"),
    ("U$_$TA_$_TINNER_$__$$_RUN", "U.TA.TINNER.RUN"),
    ("GENERICS.DEFAULTS$_$THASHSERVICE$1$CRCEBCF4973_$__$$_LOOKUP$$LONGINT", "GENERICS.DEFAULTS.THASHSERVICE.LOOKUP"),
    ("SYSTEM_$$_$assign$VARIANT$$UTF8STRING", "SYSTEM.operator :="),
    ("INIT$_$JSONSCANNER", "JSONSCANNER.initialization"),
    ("FINALIZE$_$P$T1", "T1.finalization"),
    ("fpc_ansistr_concat", "fpc_ansistr_concat"),
    ("_UNICODEDATA_$$_init_implicit$", "UNICODEDATA.init_implicit"),
    ("__$dll$kernel32$GetThreadPriority", None),
    ("INIT$$SYSTEM", None),
    (".text", None),
    ("", None),
])
def test_demangle(sym, want):
    assert fpcsigs.demangle(sym) == want


def test_case_map_restores_spelling_from_sources(tmp_path):
    (tmp_path / "a.pp").write_text("unit SysUtils; type TFPList = class function CheckIndex(i: Integer): Boolean; end;\n"
                                   "begin tfplist.CHECKINDEX; TFPList.CheckIndex; checkindex end.", encoding="latin-1")
    (tmp_path / "b.inc").write_text("procedure CheckIndex; // sysutils is a unit", encoding="latin-1")
    cm = fpcsigs.CaseMap()
    assert cm.add_dir(tmp_path) == 2
    assert cm.fix("SYSUTILS.TFPLIST.CHECKINDEX") == "SysUtils.TFPList.CheckIndex"
    assert cm.fix("SYSUTILS.UNKNOWNTHING") == "SysUtils.UNKNOWNTHING"
    assert cm.fix("fpc_copy") == "fpc_copy"                     # not upper case: kept
    assert fpcsigs.display_name("CLASSES$_$TLIST_$__$$_ADD", cm) == "CLASSES.TLIST.ADD"
    assert fpcsigs.CaseMap().fix("A.B") == "A.B"


def test_interface_names_from_sources_and_names_file(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "x.pp").write_text("type\n  IGreeter = interface(IUnknown)\n    ['{B4F1A2C3-1111-2222-3333-444455556666}']\n"
                              "  IPlain = interface ['{aabbccdd-0000-1111-2222-333344445555}']\n", encoding="latin-1")
    guids = fpcsigs.guid_names([src])
    assert guids == {"{B4F1A2C3-1111-2222-3333-444455556666}": "IGreeter",
                     "{AABBCCDD-0000-1111-2222-333344445555}": "IPlain"}
    assert fpcsigs.load_names(tmp_path, "3.2.2") == (None, "none")
    fpcsigs.write_names(tmp_path, "3.2.2", {"TComponent": {23: "Notification"}}, guids)
    names, tag = fpcsigs.load_names(tmp_path, "3.2.2")
    assert names == ({"TComponent": {23: "Notification"}}, guids) and tag != "none"
    assert fpcsigs.load_names(None, "3.2.2") == (None, "none")
    (tmp_path / "fpc-3.2.2-names.json").write_text("{broken", encoding="utf-8")
    assert fpcsigs.load_names(tmp_path, "3.2.2") == (None, "none")


# ── scan of a program with symbols, database, matching ───────────────────────

BASE = 0x400000
PBASE = 0x50000000                  # image base of the PE written by make_bpl
# push ebp; mov ebp,esp; sub esp,16; mov eax,[abs]; call rel32; mov esp,ebp; pop ebp; ret
CODE = bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10, 0xA1, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x89, 0xEC, 0x5D, 0xC3])


def routine(abs_addr: int, rel: int, seed: int = 0) -> bytes:
    b = bytearray(CODE)
    b[7:11] = struct.pack("<I", abs_addr)
    b[12:16] = struct.pack("<i", rel)
    b[5] = 0x10 + seed
    return bytes(b)


def with_symbols(path: Path, syms: dict[str, int]) -> None:
    """Append a COFF symbol table ({name: rva}, all in section 1) to a PE written by ``make_bpl``."""
    raw = bytearray(path.read_bytes())
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    text_va = struct.unpack_from("<I", raw, pe + 24 + struct.unpack_from("<H", raw, pe + 20)[0] + 12)[0]
    table = bytearray()
    strtab = bytearray()
    for name, rva in syms.items():
        off = 4 + len(strtab)
        strtab += name.encode() + b"\0"
        table += struct.pack("<II", 0, off) + struct.pack("<IhHBB", rva - text_va, 1, 0, 2, 0)
    struct.pack_into("<II", raw, pe + 12, len(raw), len(syms))
    path.write_bytes(bytes(raw) + bytes(table) + struct.pack("<I", 4 + len(strtab)) + bytes(strtab))


@pytest.fixture
def program(tmp_path):
    pytest.importorskip("capstone")
    path = tmp_path / "ref.exe"
    routines = [("a", routine(PBASE + 0x2000, 0x100, 1)), ("b", routine(PBASE + 0x2010, 0x200, 2)),
                ("c", routine(PBASE + 0x2020, 0x300, 3))]
    where = make_bpl(path, routines)
    with_symbols(path, {"CLASSES$_$TLIST_$__$$_ADD$POINTER$$LONGINT": where["a"],
                        "SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING": where["b"],
                        "fpc_ansistr_concat": where["c"], "__$dll$kernel32$Sleep": where["c"] + 20})
    return path, where


def test_read_coff_and_scan(program):
    path, where = program
    syms = fpcsigs.read_coff(path)
    assert {n: r for n, r, _x in syms}["fpc_ansistr_concat"] == where["c"]
    psize, recs = fpcsigs.scan_exe(str(path))
    assert psize == 4
    by = {r[0]: r for r in recs}
    assert sorted(by) == ["CLASSES.TLIST.ADD", "SYSUTILS.INTTOSTR", "fpc_ansistr_concat"]
    name, dump, mask, _calls = by["CLASSES.TLIST.ADD"]
    assert len(dump) == 20 and mask[7:11] == bytes([MASK]) * 4 and mask[12:16] == bytes([MASK]) * 4
    assert dump[0:5] == CODE[0:5] and mask[0:7] == bytes(7)


def test_stripped_program_is_an_error(tmp_path):
    pytest.importorskip("capstone")
    path = tmp_path / "s.exe"
    make_bpl(path, [("a", routine(BASE + 0x2000, 0x100))])
    assert fpcsigs.read_coff(path) == []
    with pytest.raises(fpcsigs.FpcError):
        fpcsigs.scan_exe(str(path))


@pytest.fixture
def fpc_proj(program, tmp_path):
    """A project with an FPC binary that holds the same routines at other addresses and one unknown routine."""
    from test_tools import make_ctx
    _path, _where = program
    _psize, recs = fpcsigs.scan_exe(str(program[0]))
    sig = tmp_path / "sigs"
    sig.mkdir()
    delphisigs.write_sigdb(sig / "fpc-3.2.2-32.sigdb", 30202, 4, [r for r in recs if idr.usable(r[2])],
                           {"toolchain": "fpc", "fpc": "3.2.2"})
    delphisigs.write_sigdb(sig / "fpc-3.1.0-32.sigdb", 30100, 4, [r for r in recs[:1]])    # another version
    delphisigs.write_sigdb(sig / "30-32.sigdb", 30, 4, [("System.Delphi.Thing", routine(0, 0, 9), bytes(7) + b"\xff" * 4 + b"\0" + b"\xff" * 4 + bytes(4))])
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    pe = Pe(4)
    pe.text[0:20] = routine(BASE + 0x2800, 0x50, 1)               # CLASSES.TLIST.ADD at other addresses
    pe.text[64:84] = routine(BASE + 0x2900, 0x70, 3)              # fpc_ansistr_concat
    pe.text[128:148] = routine(BASE + 0x2A00, 0x90, 8)            # program code
    sha = "ab" * 32
    pe.write(art / sha)
    base = pe.base + 0x1000
    return ctx, st, ix, art, sha, sig, base


def add_binary(st, ix, sha, toolchain, ver, base):
    bid = st.upsert_binary(sha, "p.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain=toolchain, toolchain_ver=ver, analysis_profile="p")
    ix.set_status(st, bid, "ready")
    st.insert_functions(bid, [{"entry": base + off, "name": f"FUN_{base + off:08x}", "name_state": "auto", "size": 20}
                              for off in (0, 64, 128)])
    return bid


def test_files_for_selects_the_database_of_the_fpc_version(fpc_proj):
    ctx, st, ix, art, sha, sig, base = fpc_proj
    bid = add_binary(st, ix, sha, "fpc", "3.2.2", base)
    b = st.get_binary_by_id(bid)
    assert [f.label for f in idr.files_for(b, None, sig, None)] == ["fpc3.2.2-32"]
    assert [f.label for f in idr.sig_files(sig, 4)] == ["sig30-32"]            # the Delphi list never holds FPC files
    assert [f.label for f in fpcsigs.sig_files(sig, 4)] == ["fpc3.1.0-32", "fpc3.2.2-32"]
    assert fpcsigs.sig_files(sig, 8) == [] and fpcsigs.sig_files(None, 4) == []
    other = st.upsert_binary("cd" * 32, "q.exe", format="pe32", arch="x86", pointer_size=4, toolchain="fpc",
                             toolchain_ver="3.0.4")
    assert idr.files_for(st.get_binary_by_id(other), None, sig, None) == []


def test_fpc_binary_is_named_from_its_database(fpc_proj):
    ctx, st, ix, art, sha, sig, base = fpc_proj
    bid = add_binary(st, ix, sha, "fpc", "3.2.2", base)
    b = st.get_binary_by_id(bid)
    assert idr.stale(st, b, None, sig) and idr.ensure(st, b, art / sha, None, sig)
    assert idr.hits(st, bid) == {base: "CLASSES.TLIST.ADD", base + 64: "fpc_ansistr_concat"}
    assert idr.info(st, bid).startswith("fpc3.2.2-32: 2 of 3 unnamed functions named")
    assert not idr.stale(st, b, None, sig)
    assert base in delphi.runtime_addrs(st, bid)
    (sig / "fpc-3.2.2-32.sigdb").unlink()                                      # database removed: result cleared
    assert idr.stale(st, b, None, sig) and idr.ensure(st, b, art / sha, None, sig) and idr.hits(st, bid) == {}


def test_delphi_binary_never_uses_fpc_databases(fpc_proj):
    ctx, st, ix, art, sha, sig, base = fpc_proj
    bid = add_binary(st, ix, sha, "delphi", None, base)
    b = st.get_binary_by_id(bid)
    assert [f.label for f in idr.files_for(b, None, sig, None)] == ["sig30-32"]
    assert idr.ensure(st, b, art / sha, None, sig)
    assert "CLASSES.TLIST.ADD" not in idr.hits(st, bid).values()


def test_oracle_counts_right_wrong_and_none(tmp_path, fpc_proj):
    from test_fpc import FpcPe
    _ctx, _st, _ix, _art, _sha, sig, _base = fpc_proj
    pe = FpcPe(4)
    for i, (seed, a, r) in enumerate(((1, 0x2800, 0x50), (2, 0x2900, 0x60), (7, 0x2A00, 0x70), (5, 0x2B00, 0x80))):
        pe.text[i * 64:i * 64 + 20] = routine(BASE + a, r, seed)
    path = tmp_path / "o.exe"
    pe.write(path)
    with_symbols(path, {"CLASSES$_$TLIST_$__$$_ADD": 0x1000, "SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING": 0x1040,
                        "CLASSES$_$TLIST_$__$$_OTHER": 0x1080, "P$T1_$$_MAIN": 0x10C0, "FINALIZE$_$P$T1": 0x1100})
    res = fpcsigs.measure(path, sig)
    assert (res.compiler, res.bits, res.routines, res.library, res.own_total) == (30202, 32, 5, 3, 2)
    s0 = res.stages[0]
    assert (s0.all.n, s0.all.right, s0.all.wrong, s0.all.none) == (3, 2, 0, 1)
    assert (s0.big.n, s0.big.right) == (3, 2)
    assert res.own_named == 0
    assert fpcsigs.measure(path, sig, {"classes"}).library == 1               # the unit "Classes" is the program's own


def test_measure_needs_a_version_string_and_symbols(tmp_path, fpc_proj):
    _ctx, _st, _ix, _art, _sha, sig, _base = fpc_proj
    path = tmp_path / "m.exe"
    make_bpl(path, [("a", routine(BASE + 0x2000, 0x100))])
    with pytest.raises(fpcsigs.FpcError):
        fpcsigs.measure(path, sig)
    with_symbols(path, {"CLASSES$_$TLIST_$__$$_ADD": 0x1000})
    with pytest.raises(fpcsigs.FpcError):                                    # no FPC version string: no database
        fpcsigs.measure(path, sig)


def test_vslot_names_from_symbols_of_reference_program(tmp_path):
    """Slot names come from the symbols of the code each class holds in a slot (overrides share the name)."""
    from test_fpc import FpcPe
    pe = FpcPe(4)
    pe.fclass("TObject", None, "System", 4, virtuals=13)
    pe.fclass("TComp", "TObject", "Classes", 8, virtuals=15)
    pe.fclass("TWin", "TComp", "Controls", 12, virtuals=15)
    path = tmp_path / "v.exe"
    pe.write(path)
    # TComp slots 13 and 14 hold stub code "TComp.v13" / "TComp.v14"; TWin overrides slot 14 with its own stub
    syms = {"CLASSES$_$TCOMP_$__$$_LOADED": pe.code["TComp.v13"] - 0x400000,
            "CLASSES$_$TCOMP_$__$$_NOTIFICATION": pe.code["TComp.v14"] - 0x400000,
            "CONTROLS$_$TWIN_$__$$_NOTIFICATION": pe.code["TWin.v14"] - 0x400000}
    with_symbols(path, syms)
    got = fpcsigs.vslot_names(path)
    assert got == {"TComp": {13: "LOADED", 14: "NOTIFICATION"}}


def test_build_needs_a_compiler(tmp_path):
    with pytest.raises(fpcsigs.FpcError):
        fpcsigs.probe_compiler(tmp_path / "missing" / "fpc.exe")
    assert fpcsigs.find_compilers(tmp_path) == []
    (tmp_path / "bin" / "i386-win32").mkdir(parents=True)
    (tmp_path / "bin" / "i386-win32" / "fpc.exe").write_bytes(b"x")
    assert fpcsigs.find_compilers(tmp_path) == [tmp_path / "bin" / "i386-win32" / "fpc.exe"]


# ── keep-all link (routines the reference program never calls) ────────────────

def make_obj(path: Path, syms: list[tuple[str, int, int]], long_name: str | None = None) -> None:
    """Minimal COFF object: section 1 is code, section 2 is data. ``syms``: (name, section, storage class)."""
    strtab = b""
    names = list(syms) + ([(long_name, 1, 2)] if long_name else [])
    ents = b""
    for nm, sec, sc in names:
        raw = nm.encode()
        if len(raw) <= 8:
            field = raw.ljust(8, b"\0")
        else:
            field = b"\0\0\0\0" + struct.pack("<I", 4 + len(strtab))
            strtab += raw + b"\0"
        ents += field + struct.pack("<IhHBB", 0, sec, 0, sc, 0)
    sect = lambda ch: b".x".ljust(8, b"\0") + struct.pack("<IIIIIIHHI", 0, 0, 0, 0, 0, 0, 0, 0, ch)
    hdr = 20 + 80
    path.write_bytes(struct.pack("<HHIIIHH", 0x14C, 2, 0, hdr, len(names), 0, 0)
                     + sect(0x60000020) + sect(0xC0000040) + ents + struct.pack("<I", 4 + len(strtab)) + strtab)


def test_object_symbols_lists_global_code_symbols(tmp_path):
    o = tmp_path / "dialogs.o"
    make_obj(o, [("SHOWMSG", 1, 2), ("DATAVAR", 2, 2), ("LOCALFN", 1, 3), ("UNDEF", 0, 2)],
             long_name="DIALOGS_$$_SHOWMESSAGE$ANSISTRING")
    assert fpcsigs.object_symbols(o) == ["SHOWMSG", "DIALOGS_$$_SHOWMESSAGE$ANSISTRING"]


def test_keep_symbols_reads_only_the_listed_units(tmp_path):
    make_obj(tmp_path / "Dialogs.o", [("A1", 1, 2), ("A2", 1, 2)])
    make_obj(tmp_path / "other.o", [("B1", 1, 2)])
    assert fpcsigs.keep_symbols(["dialogs", "nounit"], [tmp_path]) == ["A1", "A2"]


def _fake_compiler(tmp_path: Path, fail_with_keep: bool) -> fpcsigs.Compiler:
    """A Python script that stands in for fpc: records its command line, writes the exe."""
    log = tmp_path / "calls.txt"
    script = tmp_path / "fakefpc.py"
    script.write_text(
        "import sys, pathlib\n"
        f"a = sys.argv[1:]\nopen(r'{log}', 'a').write(' '.join(a) + '\\n')\n"
        f"if {fail_with_keep!r} and 'airlock_keep' in open(a[-1]).read():\n    print('Error: undefined reference'); sys.exit(1)\n"
        "fe = [x[3:] for x in a if x.startswith('-FE')][0]\n"
        "pathlib.Path(fe, pathlib.Path(a[-1]).stem + '.exe').write_bytes(b'MZ')\n")
    bat = tmp_path / "fakefpc.bat"
    bat.write_text(f'@"{__import__("sys").executable}" "{script}" %*\n')
    return fpcsigs.Compiler(bat, "3.2.2", "i386", "win32")


def test_write_keep_object_has_one_relocation_per_symbol(tmp_path):
    for bits, machine, rtype in ((32, 0x14C, 6), (64, 0x8664, 1)):
        o = tmp_path / f"k{bits}.o"
        fpcsigs.write_keep_object(o, "airlock_keep", ["SYMBOL_ONE", "B"], bits)
        d = o.read_bytes()
        mach, nsec, _t, symptr, nsym = struct.unpack_from("<HHIII", d, 0)
        assert (mach, nsec, nsym) == (machine, 1, 3)
        size, rawptr, relptr, _l, nrel = struct.unpack_from("<IIIIH", d, 20 + 16)
        assert (size, nrel) == (2 * bits // 8, 2)
        rel = [struct.unpack_from("<IIH", d, relptr + 10 * i) for i in range(2)]
        assert rel == [(0, 1, rtype), (bits // 8, 2, rtype)]
        assert d[symptr:symptr + 8] == b"airlock_" or d[symptr:symptr + 4] == bytes(4)    # long name: string table


def test_write_keep_objects_split_in_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(fpcsigs, "_KEEP_CHUNK", 2)
    names = fpcsigs.write_keep_objects(tmp_path, "lclmega", ["A", "B", "C"], 32)
    assert names == ["airlock_keep_lclmega_0", "airlock_keep_lclmega_1"]
    assert all((tmp_path / f"{n}.o").is_file() for n in names)


def test_compile_makes_the_program_refer_to_every_routine(tmp_path):
    comp = _fake_compiler(tmp_path, False)
    objs = tmp_path / "o"
    objs.mkdir()
    make_obj(objs / "dialogs.o", [("DIALOGS_SHOWMESSAGE", 1, 2)])
    exe = fpcsigs._compile(comp, ["Dialogs"], tmp_path / "w", "lclmega", [], lambda _m: None, [objs])
    assert exe.is_file()
    pas = (tmp_path / "w" / "lclmega.pas").read_text()
    assert "{$L airlock_keep_lclmega_0.o}" in pas and "external name 'airlock_keep_lclmega_0'" in pas
    assert "if @airlock_keep_lclmega_0 = nil" in pas
    assert (tmp_path / "w" / "airlock_keep_lclmega_0.o").is_file()


def test_compile_falls_back_to_the_normal_link(tmp_path):
    comp = _fake_compiler(tmp_path, True)
    objs = tmp_path / "o"
    objs.mkdir()
    make_obj(objs / "dialogs.o", [("DIALOGS_SHOWMESSAGE", 1, 2)])
    said: list[str] = []
    exe = fpcsigs._compile(comp, ["Dialogs"], tmp_path / "w", "lclmega", [], said.append, [objs])
    assert exe.is_file() and any("keep-all link failed" in m for m in said)
    assert "airlock_keep" not in (tmp_path / "w" / "lclmega.pas").read_text()


# ── look-alike names (Create / Destroy of many classes have the same bytes) ───

def _kb_with(names: list[str]) -> idr.Kb:
    kb = idr.Kb("fpc-3.2.2-32")
    kb.procs = [idr.Proc(n, 0, 0, 8, 8) for n in names]
    return kb


def test_class_of_name():
    assert idr._class_of("Graphics.TFont.Destroy") == "tfont"
    assert idr._class_of("Dialogs.ShowMessage") == ""


def test_class_table_picks_the_owner_class(monkeypatch):
    names = ["Graphics.TFont.Destroy", "Graphics.TPen.Destroy", "Graphics.TBrush.Destroy"]
    kb = _kb_with(names)
    out = {0x1000: list(names)}
    kept = {0x1000: [0, 1, 2]}
    monkeypatch.setattr(idr, "_fpc_owners", lambda _img: {0x1000: {"tpen"}})
    idr._fpc_disambiguate(kb, None, out, kept)
    assert out == {0x1000: ["Graphics.TPen.Destroy"]} and kept == {0x1000: [1]}


def test_unambiguous_matches_order_the_rest_and_big_sets_are_dropped(monkeypatch):
    monkeypatch.setattr(idr, "_fpc_owners", lambda _img: {})
    kb = _kb_with([])
    many = [f"U{i}.TC{i}.Destroy" for i in range(6)]
    out = {1: ["Graphics.TPen.Destroy", "Graphics.TBrush.Destroy"], 2: ["Graphics.TBrush.Close"],
           3: ["Graphics.TBrush.Open"], 4: many}
    idr._fpc_disambiguate(kb, None, out, {k: [] for k in out})
    assert out[1] == ["Graphics.TBrush.Destroy", "Graphics.TPen.Destroy"]    # TBrush has two sure matches
    assert 4 not in out
