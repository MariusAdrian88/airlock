"""RTTI consensus database: names from the extended RTTI of several synthetic programs (all names invented).

Synthetic 32-bit and 64-bit PEs from ``test_delphi.Pe``: each program has runtime classes (units ``System.*``)
and one program class; the methods carry small x86 bodies. No Delphi or other install is needed."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

pytest.importorskip("capstone")

from airlock.server import delphi, delphirtti as rt, delphisigs, idr
from airlock.server.cpp import Image
from test_delphi import DATA_VA, TEXT_VA, Pe

COMPILER = b"Embarcadero Delphi for Win32 compiler version 30.0 (22858)\0"


def body(psize: int, seed: int, abs_off: int = 0x40, call: int = 0x300) -> bytes:
    """A routine of about 20 bytes: constant (kept), absolute address and call target (masked)."""
    if psize == 4:
        return (b"\x55\x8b\xec\xb8" + struct.pack("<I", seed) + b"\xa1" + struct.pack("<I", 0x400000 + DATA_VA + abs_off)
                + b"\x03\xc0\xe8" + struct.pack("<I", call) + b"\x5d\xc3")
    return (b"\x48\x8b\xc1\xb8" + struct.pack("<I", seed) + b"\x48\x03\xc0\x48\x83\xc0\x07\xe8"
            + struct.pack("<I", call) + b"\xc3")


class RPe(Pe):
    """``bodies``: {"Class.method": bytes} placed as the code of the RTTI methods."""

    def __init__(self, psize: int, bodies: dict[str, bytes]) -> None:
        super().__init__(psize)
        self.bodies = bodies

    def stub(self, name: str) -> int:
        raw = self.bodies.get(name, b"\xc3")
        va = self.base + TEXT_VA + self.tpos
        self.text[self.tpos:self.tpos + len(raw)] = raw
        self.tpos += (len(raw) + 15) // 16 * 16
        self.code[name] = va
        return va


PUBLIC = 0x42
NAMES = ("Run", "Stop", "Same1", "Same2")


def program(path: Path, psize: int, skew: int, *, run: int = 1, stop: int | None = 2, extra: bool = True,
            stubs: bool = True, comment: bytes = b"") -> RPe:
    """One program. ``skew`` changes the addresses (absolute operands, call targets) of every body; ``run``
    / ``stop`` are the constants of two methods (``stop`` None: no method), ``comment`` makes the file unique."""
    b: dict[str, bytes] = {"TFoo.Run": body(psize, run, 0x40 + skew, 0x300 + skew)}
    if stop is not None:
        b["TFoo.Stop"] = body(psize, stop, 0x50 + skew, 0x310 + skew)
    b["TFoo.Same1"] = body(psize, 77, 0x60 + skew, 0x320 + skew)            # identical code: an alias pair
    b["TFoo.Same2"] = body(psize, 77, 0x60 + skew, 0x320 + skew)
    b["TMine.Secret"] = body(psize, 5, 0x70 + skew, 0x330 + skew)            # program class
    if stubs:
        for i in range(7):
            b[f"TStub.M{i}"] = body(psize, 9, 0x80 + skew, 0x340 + skew)      # seven names, one shape
    b["TList<Prog.TMine>.Add"] = body(psize, 11, 0x90 + skew, 0x350 + skew)
    pe = RPe(psize, b)
    pe.klass("TObject", None, "System", 8)
    rtti = [(m, PUBLIC, -1) for m in ("Run", "Same1", "Same2")] + ([("Stop", PUBLIC, -1)] if stop is not None else [])
    pe.klass("TFoo", "TObject", "System.Classes", 16, rtti=tuple(rtti))
    pe.klass("TMine", "TObject", "Prog.Units", 16, rtti=(("Secret", PUBLIC, -1),))
    if stubs:
        pe.klass("TStub", "TObject", "System.SysUtils", 16, rtti=tuple((f"M{i}", PUBLIC, -1) for i in range(7)))
    if extra:
        pe.klass("TList<Prog.TMine>", "TObject", "System.Generics.Collections", 16, rtti=(("Add", PUBLIC, -1),))
    pe.put(pe.alloc(len(COMPILER), 1), COMPILER + comment)
    pe.write(path)
    return pe


def corpus(tmp_path: Path, psize: int) -> tuple[Path, Path]:
    """Product one: two different files and a byte copy of the first. Product two: one file."""
    one, two = tmp_path / "prodone", tmp_path / "prodtwo"
    one.mkdir()
    two.mkdir()
    program(one / "a.exe", psize, 0x000, stop=2)
    program(one / "b.exe", psize, 0x100, stop=2, comment=b"b")            # same code, other addresses
    (one / "copy.dll").write_bytes((one / "a.exe").read_bytes())          # identical file: counts once
    program(two / "c.exe", psize, 0x200, stop=None, comment=b"c")        # no Stop; another address layout
    return one, two


def names_of(path: Path) -> set[str]:
    return {p.name for p in delphisigs.read_sigdb(path).procs}


def test_names_and_units():
    assert rt.normalize_class("TList<System.Rtti.TFoo>.TEnumerator") == "TList<T>.TEnumerator"
    assert rt.normalize_class("TDictionary<string, TList<Integer>>") == "TDictionary<T>"
    assert rt.normalize_class("TComparer<Prog.TPair<System.string,Prog.TLong<T,Prog.TCut") == "TComparer<T>"
    assert rt.normalize_class("TA<X>.TB<Y>") == "TA<T>.TB<T>"
    assert rt.routine_name("System.Classes", "TFoo", "Run") == "System.Classes.TFoo.Run"
    assert rt.allowed_unit("System.Classes") and rt.allowed_unit("Vcl.Forms") and rt.allowed_unit("SysUtils")
    assert not rt.allowed_unit("Prog.Units") and not rt.allowed_unit("")
    assert not rt.allowed_unit("IdFTP") and rt.allowed_unit("IdFTP", indy=True)


@pytest.mark.parametrize("psize", [4, 8])
def test_scan_takes_runtime_classes_only(tmp_path, psize):
    program(tmp_path / "a.exe", psize, 0)
    s = rt.scan_binary(str(tmp_path / "a.exe"))
    assert s is not None and s.compiler == 30 and s.psize == psize
    got = {n for n, _d, _m in s.records}
    assert "System.Classes.TFoo.Run" in got and "System.Generics.Collections.TList<T>.Add" in got
    assert not any("Secret" in n or "Prog" in n for n in got)
    # the same code at other addresses has the same shape
    program(tmp_path / "b.exe", psize, 0x180, comment=b"x")
    s2 = rt.scan_binary(str(tmp_path / "b.exe"))
    a = {n: (d, m) for n, d, m in s.records}
    b = {n: (d, m) for n, d, m in s2.records}
    assert a["System.Classes.TFoo.Run"] == b["System.Classes.TFoo.Run"]
    assert a["System.Classes.TFoo.Run"][1].count(0xFF) > 0


def test_non_delphi_and_packaged_programs_are_skipped(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ" + b"\0" * 8000)
    assert rt.scan_binary(str(p)) is None
    pe = RPe(4, {})
    pe.klass("TObject", None, "System", 8)
    pe.write(tmp_path / "nocompiler.exe")                    # no compiler string: the RTL is in a package
    assert rt.scan_binary(str(tmp_path / "nocompiler.exe")) is None


@pytest.mark.parametrize("psize", [4, 8])
def test_votes_files_products_aliases_and_stubs(tmp_path, psize):
    one, two = corpus(tmp_path, psize)
    out = tmp_path / "out"
    res = rt.build([one, two], out, min_binaries=3, min_products=1, jobs=1)
    assert [(r.compiler, r.psize, r.binaries) for r in res] == [(30, psize, 3)]      # the copy counts once
    got = names_of(res[0].path)
    assert res[0].path.name == f"rtti-30-{psize * 8}.sigdb"
    assert "System.Classes.TFoo.Run" in got                                         # in all three files
    assert "System.Classes.TFoo.Stop" not in got                                    # only two files have it
    assert {"System.Classes.TFoo.Same1", "System.Classes.TFoo.Same2"} <= got        # aliases keep both names
    assert not any(n.startswith("System.SysUtils.TStub") for n in got)             # seven names: a stub shape
    assert "System.Generics.Collections.TList<T>.Add" in got
    assert not any("Secret" in n for n in got)                                       # program class
    assert res[0].stubs == 1 and res[0].cross_product == len(got)
    assert delphisigs.read_sigdb_header(res[0].path)["kind"] == "rtti"
    # two files are enough for Stop, but not when both products must agree
    res2 = rt.build([one, two], tmp_path / "out2", min_binaries=2, min_products=1, jobs=1)
    assert "System.Classes.TFoo.Stop" in names_of(res2[0].path)
    assert res2[0].single_product >= 1
    res3 = rt.build([one, two], tmp_path / "out3", min_binaries=2, min_products=2, jobs=1)
    assert "System.Classes.TFoo.Stop" not in names_of(res3[0].path)
    assert "System.Classes.TFoo.Run" in names_of(res3[0].path)


def test_exclude_leaves_a_file_out(tmp_path):
    one, two = corpus(tmp_path, 4)
    res = rt.build([one, two], tmp_path / "out", min_binaries=3, jobs=1, exclude=[two / "c.exe"])
    assert res == []                                          # two distinct files remain: no name has 3 votes
    res = rt.build([one, two], tmp_path / "out", min_binaries=2, jobs=1, exclude=[one / "copy.dll"])
    assert res and res[0].binaries == 2                       # the copy is the same file as a.exe: both go


def test_build_errors(tmp_path):
    with pytest.raises(rt.RttiError):
        rt.build([], tmp_path / "o")
    with pytest.raises(rt.RttiError):
        rt.build([tmp_path / "missing"], tmp_path / "o")


@pytest.mark.parametrize("psize", [4, 8])
def test_database_names_a_new_program(tmp_path, psize):
    one, two = corpus(tmp_path, psize)
    res = rt.build([one, two], tmp_path / "out", min_binaries=3, jobs=1)
    target = tmp_path / "t"
    target.mkdir()
    program(target / "t.exe", psize, 0x350, comment=b"t", extra=False, stubs=False)
    img = Image.from_pe(target / "t.exe")
    kb = idr.load_kb(idr.KbFile(res[0].path, "rtti30", "30", True, res[0].path.stat().st_size, True, True))
    foo = {c.name: c for c in delphi.parse_classes(img)}["TFoo"]
    entries = [(m.addr, None) for m in foo.methods if m.kind.startswith("rtti")]
    hits = idr.match_all(kb, img, entries)
    by_name = {m.name: hits.get(m.addr) for m in foo.methods if m.kind.startswith("rtti")}
    assert by_name["Run"] == ["System.Classes.TFoo.Run"]
    assert sorted(by_name["Same1"]) == ["System.Classes.TFoo.Same1", "System.Classes.TFoo.Same2"]
    assert by_name["Stop"] is None                            # not in the database


def test_files_listing_and_pick_order(tmp_path):
    sig = tmp_path / "sig"
    sig.mkdir()
    for n in ("30-32.sigdb", "rtti-30-32.sigdb", "rtti-30-64.sigdb", "rtti-31-32.sigdb"):
        (sig / n).write_bytes(b"x" * 100)
    got = idr.sig_files(sig, 4)
    assert [(f.label, f.rtti) for f in got] == [("sig30-32", False), ("rtti30-32", True), ("rtti31-32", True)]
    assert [f.label for f in idr.sig_files(sig, 8)] == ["rtti30-64"]
    assert idr.kb_signature(got) != idr.kb_signature(got[:2])


def test_pick_runs_exact_then_rtti_then_knowledge_bases(tmp_path):
    """A routine named by the exact database keeps that name; the RTTI database names the next one."""
    img_path = tmp_path / "t.exe"
    pe = RPe(4, {"TFoo.Run": body(4, 1), "TFoo.Stop": body(4, 2), "TFoo.Same1": body(4, 3)})
    pe.klass("TObject", None, "System", 8)
    pe.klass("TFoo", "TObject", "System.Classes", 16, rtti=(("Run", PUBLIC, -1), ("Stop", PUBLIC, -1), ("Same1", PUBLIC, -1)))
    pe.put(pe.alloc(len(COMPILER), 1), COMPILER)
    pe.write(img_path)
    img = Image.from_pe(img_path)
    run, stop, same = (pe.code[f"TFoo.{m}"] for m in ("Run", "Stop", "Same1"))

    def db(name: str, comp: int, recs: list[tuple[str, int]]) -> Path:
        rec = []
        for n, seed in recs:
            raw = body(4, seed)
            mask = bytearray(len(raw))
            mask[5 + 4 + 1 - 1:5 + 4 + 1 + 3] = b"\xff" * 4   # placeholder, replaced below
            mask = bytearray(len(raw))
            for k in range(9, 13):
                mask[k] = 0xFF                               # the absolute address
            for k in range(16, 20):
                mask[k] = 0xFF                               # the call operand
            d = bytes(0 if mask[i] else raw[i] for i in range(len(raw)))
            rec.append((n, d, bytes(mask)))
        p = tmp_path / name
        delphisigs.write_sigdb(p, comp, 4, rec)
        return p

    db("30-32.sigdb", 30, [("System.Classes.TFoo.Run", 1)])
    db("rtti-30-32.sigdb", 30, [("System.Classes.TFoo.RunRtti", 1), ("System.Classes.TFoo.Stop", 2)])
    files = idr.sig_files(tmp_path, 4)
    funcs = [(run, None), (stop, None), (same, None)]
    label, hits, notes = idr._pick(files, img, funcs)
    assert hits[run] == ["System.Classes.TFoo.Run"]                  # exact database first
    assert hits[stop] == ["System.Classes.TFoo.Stop"]                # then the RTTI database
    assert same not in hits
    assert label == "sig30-32+rtti30-32"
