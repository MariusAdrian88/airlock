"""Exact-version Free Pascal RTL / LCL signatures (DESIGN 11 "Free Pascal (FPC / Lazarus)", "Signatures").

A Free Pascal program links the RTL (and the LCL of a Lazarus program) as the machine code of the units that
shipped with the compiler: the same bytes in every program of that compiler version and target. The build
compiles reference programs that ``use`` the units of a local FPC install (and of a Lazarus install) with ``-g``,
so the linker keeps the whole units and the executable keeps its COFF symbol table. The symbols are the true
names; the code of each routine is dumped and masked exactly like the Delphi package routines
(``delphisigs.scan_named``): relocations and ``rel32`` operands outside the routine, RIP-relative operands
(64-bit) and absolute 32-bit addresses inside the image (FPC executables have no ``.reloc`` section).

Output: ``fpc-<version>-<32|64>.sigdb``, the sigdb file format (``delphisigs.write_sigdb``), used by
``idr`` for binaries with toolchain ``fpc`` and the same ``toolchain_ver``. A program compiled with other
options than the shipped units (the LCL built by Lazarus with its own flags, a unit of the program that
the program shares with the RTL) has other code: only the exact bytes match.

Mangled names (``CLASSES$_$TLIST_$__$$_ADD$POINTER$$LONGINT``) are upper case except the ``fpc_*`` helpers.
``demangle`` returns ``Unit.Class.Method``; when the source folders of the install are given the case of each
identifier is restored from the most frequent spelling in the sources. Parameter lists are not kept.
"""

from __future__ import annotations

import bisect
import collections
import json
import logging
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from airlock.server import delphi, delphisigs as ds, idr
from airlock.server.cpp import Image

log = logging.getLogger("airlock")

FPC_SIG_NAME = re.compile(r"^fpc-(\d+\.\d+\.\d+)-(32|64)\.sigdb$")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MISSING = re.compile(r"Can't find unit (\S+) used by (\S+)", re.I)
_SOURCE_EXT = (".pp", ".pas", ".inc", ".lpr")


class FpcError(RuntimeError):
    """A signature database that cannot be built or measured."""


# -- COFF symbols -------------------------------------------------------------------------------

def read_coff(path: Path) -> list[tuple[str, int, int]]:
    """(name, rva, size hint 0) of the symbols that lie in an executable section of a PE file. The COFF symbol
    value of a linked image is the offset in its section. Returns [] for a stripped file."""
    d = path.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    ptr, n = struct.unpack_from("<II", d, pe + 12)
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    if not ptr or not n:
        return []
    secs: list[tuple[int, bool]] = []
    for i in range(nsec):
        o = pe + 24 + opt + 40 * i
        va = struct.unpack_from("<I", d, o + 12)[0]
        ch = struct.unpack_from("<I", d, o + 36)[0]
        secs.append((va, bool(ch & 0x20000000)))
    strtab = ptr + 18 * n
    out: list[tuple[str, int, int]] = []
    i = 0
    while i < n:
        o = ptr + 18 * i
        raw = d[o:o + 8]
        if raw[:4] == b"\0\0\0\0":
            off = struct.unpack_from("<I", raw, 4)[0]
            e = d.index(b"\0", strtab + off)
            name = d[strtab + off:e].decode("latin-1")
        else:
            name = raw.rstrip(b"\0").decode("latin-1")
        val, sn, _typ, _sc, na = struct.unpack_from("<IhHBB", d, o + 8)
        if 1 <= sn <= len(secs) and secs[sn - 1][1]:
            out.append((name, secs[sn - 1][0] + val, 0))
        i += 1 + na
    return out


# -- demangling ---------------------------------------------------------------------------------

_OPERATORS = {"assign": ":=", "add": "+", "sub": "-", "mul": "*", "fdiv": "/", "div": "div", "mod": "mod",
              "neg": "neg", "eq": "=", "lt": "<", "gt": ">", "lte": "<=", "gte": ">=", "ne": "<>", "and": "and",
              "or": "or", "xor": "xor", "not": "not", "shl": "shl", "shr": "shr", "explicit": "explicit",
              "implicit": "implicit", "inc": "inc", "dec": "dec", "in": "in"}


def _class_part(seg: str) -> str:
    """One class of a mangled class chain: ``TFOO`` or ``THASHSERVICE$1$CRCEBCF4973`` (a generic instance;
    the type arguments are not recoverable and the name stays plain)."""
    return seg.partition("$")[0]


def demangle(sym: str) -> str | None:
    """``Unit.Class.Method`` for a mangled FPC symbol; ``fpc_*`` helpers and symbols of other runtime code
    (C runtime) keep their name; None for import thunks, data-like symbols and empty names. Case is kept."""
    if not sym or sym.startswith(("__$dll$", "_$dll$", ".")):
        return None
    if sym.startswith(("INIT$_$", "FINALIZE$_$")):
        kind, _s, unit = sym.partition("$_$")
        return f"{unit.removeprefix('P$')}.{'initialization' if kind == 'INIT' else 'finalization'}"
    if sym.startswith(("INIT$$", "FINALIZE$$")):
        return None
    cls_mark = sym.find("_$__$$_")
    if cls_mark > 0 and "$_$" in sym[:cls_mark]:
        unit, _s, chain = sym[:cls_mark].partition("$_$")
        rest = sym[cls_mark + len("_$__$$_"):]
        classes = [_class_part(c) for c in chain.split("_$_")]
        path = [unit.removeprefix("P$")] + classes
    else:
        m = sym.find("_$$_")
        if m <= 0:
            return None if "$" in sym else sym
        path = [sym[:m].lstrip("_").removeprefix("P$")]
        rest = sym[m + 4:]
    name = rest.split("$$", 1)[0]
    if name.startswith("$"):
        op = name[1:].split("$", 1)[0]
        name = "operator " + _OPERATORS.get(op.lower(), op)
    else:
        name = name.split("$", 1)[0]
    if not name:
        return None
    return ".".join([p for p in path if p] + [name])


class CaseMap:
    """Spelling of identifiers: the most frequent mixed-case spelling in the Pascal sources of an install."""

    def __init__(self) -> None:
        self._count: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
        self._best: dict[str, str] = {}

    def add_dir(self, folder: Path) -> int:
        n = 0
        try:
            files = [p for p in folder.rglob("*") if p.suffix.lower() in _SOURCE_EXT]
        except OSError:
            return 0
        for p in files:
            try:
                text = p.read_text(encoding="latin-1")
            except OSError:
                continue
            for w in _IDENT.findall(text):
                if len(w) > 2:
                    self._count[w.lower()][w] += 1
            n += 1
        self._best.clear()
        return n

    def _pick(self, key: str) -> str | None:
        c = self._count.get(key)
        if not c:
            return None
        mixed = [(n, w) for w, n in c.items() if w != w.upper() and w != w.lower()]
        if mixed:
            return max(mixed)[1]
        return max((n, w) for w, n in c.items())[1]

    def fix(self, name: str) -> str:
        """``CLASSES.TFPLIST.CHECKINDEX`` -> ``Classes.TFPList.CheckIndex`` (identifiers not in the sources
        stay as they are)."""
        if not self._count or name != name.upper():
            return name
        out = []
        for part in name.split("."):
            core = part.removesuffix("<>")
            key = core.lower()
            if key not in self._best:
                self._best[key] = self._pick(key) or core
            out.append(self._best[key] + part[len(core):])
        return ".".join(out)


def display_name(sym: str, cases: CaseMap | None = None) -> str | None:
    nm = demangle(sym)
    if nm is None:
        return None
    return cases.fix(nm) if cases else nm


# -- scanning -----------------------------------------------------------------------------------

def scan_exe(path_str: str, source_dirs: tuple[str, ...] = ()) -> tuple[int, list[tuple]]:
    """(pointer size, [(name, dump, mask, calls)]) of one executable that keeps its COFF symbols. Runs in
    worker processes."""
    try:
        import capstone
    except ImportError as e:                                    # pragma: no cover
        raise ds.SigError("the build needs the capstone package (pip install capstone)") from e
    path = Path(path_str)
    syms = read_coff(path)
    if not syms:
        raise FpcError(f"{path.name} has no symbol table (a stripped or non-COFF file)")
    cases = CaseMap()
    for d in source_dirs:
        cases.add_dir(Path(d))
    img = ds._read_pe(path)
    seen: dict[int, list[str]] = {}
    for sym, rva, _x in syms:
        nm = display_name(sym, cases)
        if nm is not None:
            lst = seen.setdefault(rva, [])
            if nm not in lst:
                lst.append(nm)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if img.psize == 8 else capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = False
    top = max(va + max(vs, rs) for va, vs, _r, rs, _x in img.sections)
    recs = ds.scan_named(md, img, seen, {r for _n, r, _x in syms}, True,
                         (img.image_base, img.image_base + top))
    return img.psize, recs


# -- build --------------------------------------------------------------------------------------

@dataclass
class Compiler:
    exe: Path
    version: str
    cpu: str                     # i386 | x86_64
    os: str                      # win32 | win64

    @property
    def bits(self) -> int:
        return 64 if self.cpu == "x86_64" else 32


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 900) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FpcError(f"cannot run {cmd[0]}: {e}") from e
    return r.returncode, r.stdout + r.stderr


def probe_compiler(exe: Path) -> Compiler:
    """Version, target processor and OS of an ``fpc`` executable (``-iV``, ``-iTP``, ``-iTO``)."""
    out = []
    for flag in ("-iV", "-iTP", "-iTO"):
        rc, text = _run([str(exe), flag], timeout=60)
        if rc != 0 or not text.strip():
            raise FpcError(f"{exe} does not answer {flag}")
        out.append(text.strip().splitlines()[0].strip())
    if out[2] not in ("win32", "win64"):
        raise FpcError(f"{exe}: target OS {out[2]} (Windows only)")
    return Compiler(exe, out[0], out[1], out[2])


def find_compilers(root: Path) -> list[Path]:
    """The ``fpc.exe`` files under ``root`` (an FPC install or a Lazarus folder): ``bin/<target>/fpc.exe``."""
    found = sorted(root.glob("bin/*/fpc.exe")) + sorted(root.glob("fpc/*/bin/*/fpc.exe"))
    return found or ([root] if root.is_file() else [])


_RTL_FOLDERS = ("rtl", "rtl-objpas", "rtl-extra", "rtl-generics", "rtl-console", "fcl-base", "fcl-json", "fcl-xml",
                "fcl-registry", "fcl-process", "fcl-res", "hash", "regexpr", "paszlib", "fcl-image", "fcl-net")
_SKIP_UNIT = re.compile(r"^(cp\d.*|cpall|system|sysinit.*|ucomplex|objpas|extpas|iso7185|macpas|"
                        r"heaptrc|cmem|sharemem|lineinfo|lnfodwrf|fpintres|signals|initc)$", re.I)


# The System unit is linked per routine: a program that only uses units gets the System routines they call.
# This program calls the ones that programs use directly (file I/O, Read / Write, Str / Val, strings, sets,
# dynamic arrays, interfaces, exceptions, variants, 64-bit arithmetic, math helpers).
_TOUCH = """program systouch;
{$mode objfpc}{$H+}
uses SysUtils, Variants, Math;
type
  TRec = record a: Integer; s: AnsiString; end;
  TSet = set of 0..40;
  IFoo = interface ['{11111111-2222-3333-4444-555555555555}'] procedure P; end;
  TFoo = class(TInterfacedObject, IFoo) procedure P; end;
  EMy = class(Exception) end;
procedure TFoo.P; begin end;
var
  f: file; ft: file of Integer; t: Text; ts: string[40]; a: AnsiString; u: UnicodeString; w: WideString;
  i: Integer; i64: Int64; q: QWord; d: Double; e: Extended; sg: Single; c: Char; wc: WideChar; b: Boolean;
  buf: array[0..255] of Byte; arr: array of Integer; arr2: array of AnsiString; st: TSet; v: Variant;
  r: TRec; o: TObject; ifo: IFoo; pc: PChar; pw: PWideChar; n: LongInt; sh: ShortInt; wd: Word; lw: LongWord;
procedure Main;
begin
  Assign(f, 'x'); Reset(f, 1); BlockRead(f, buf, 10, n); BlockWrite(f, buf, 10); Seek(f, 4); i64 := FileSize(f);
  i64 := FilePos(f); Truncate(f); Close(f); Rewrite(f, 1); Close(f); Erase(f); Rename(f, 'y');
  Assign(ft, 'z'); Reset(ft); Read(ft, i); Write(ft, i); Seek(ft, 2); Close(ft); Rewrite(ft);
  Assign(t, 'a'); Reset(t); Rewrite(t); Append(t); Read(t, i); Read(t, i64); Read(t, d); Read(t, c); Read(t, a);
  ReadLn(t, ts); ReadLn(t); Write(t, i, i64, q, d, e, sg, c, wc, b, a, u, ts, pc, #10); WriteLn(t, 1.5:8:2); WriteLn(t);
  Flush(t); SetTextBuf(t, buf); Eof(t); Eoln(t); SeekEof(t); SeekEoln(t); Close(t);
  Write(i, i64, q, d, e, sg, c, wc, b, a, u, ts, pc); WriteLn(i:5, d:10:3, a, u, w); ReadLn(a); ReadLn(i);
  WriteLn(ErrOutput, a); Write(Output, a); Read(Input, c);
  Str(i, ts); Str(i64, a); Str(d:8:2, ts); Str(e, a); Str(q, a); Str(sg:6:1, ts);
  Val(a, i, n); Val(a, i64, n); Val(a, d, n); Val(a, q, n); Val(a, e, n); Val(ts, i, n); Val(a, sh, n); Val(a, wd, n);
  a := Copy(a, 2, 3); Insert('x', a, 2); Delete(a, 1, 1); i := Pos('a', a); i := Length(a); SetLength(a, 10);
  u := Copy(u, 2, 3); Insert('x', u, 2); Delete(u, 1, 1); i := Pos('a', u); SetLength(u, 10);
  w := Copy(w, 2, 3); SetLength(w, 4); ts := Copy(ts, 1, 2); Insert('x', ts, 1); Delete(ts, 1, 1); i := Pos('x', ts);
  a := a + 'x' + a; u := u + 'x' + u; ts := ts + 'y'; w := w + 'z'; a := UpCase(c) + a; c := UpCase(c);
  b := a = 'x'; b := a < 'x'; b := u = 'y'; b := u > 'z'; b := ts = 'q'; b := ts <= 'z'; b := w = 'w'; b := a <> u;
  UniqueString(a); UniqueString(u); a := ts; ts := a; u := a; a := u; w := u; u := w; a := w; w := a; a := pc; pc := PChar(a);
  u := UnicodeString(pw); pw := PWideChar(u); 
  SetLength(arr, 10); arr := Copy(arr, 1, 3); SetLength(arr2, 5); arr2 := Copy(arr2); i := High(arr); Finalize(arr2);
  SetLength(arr, 3); Initialize(arr);
  st := [1, 5, 30]; Include(st, 9); Exclude(st, 3); b := 4 in st; st := st + [2] - [1]; b := st = [1]; b := st <= st;
  st := st * [2]; b := st >= st;
  v := 1; v := 'x'; v := 2.5; v := v + v; v := v * 2; v := v / 2; b := v = v; b := v < v; i := v; d := v; a := v; v := a;
  v := VarArrayCreate([0, 1], varVariant); v := Null; b := VarIsNull(v); v := Unassigned;
  o := TFoo.Create; ifo := o as IFoo; ifo := TFoo.Create; b := Supports(o, IFoo); ifo := nil; o := nil;
  try raise EMy.Create('x'); except on E: EMy do WriteLn(E.Message); end;
  try i := 1; finally i := 2; end;
  try raise EMy.Create('y'); except raise; end;
  i := Round(d); i64 := Round(e); i64 := Trunc(d); i64 := Trunc(e); d := Frac(d); d := Int(d); d := Sqr(d); d := Sqrt(d);
  d := Sin(d); d := Cos(d); d := ArcTan(d); d := Ln(d); d := Exp(d); d := d ** 2;  d := Abs(d);
  e := Sqrt(e); i64 := i64 div 3; i64 := i64 mod 7; i64 := i64 * i64; i64 := i64 shl i; i64 := i64 shr i; q := q div 3;
  q := q mod 5; q := q * q; i64 := -i64; d := i64; e := i64; d := q; i64 := Abs(i64); i := i div 3; i := i mod 5;
  i := Random(10); Randomize; d := Random; i := Ord(c); c := Chr(i);  sg := d; d := sg; e := d; d := e;
  Move(buf, buf[1], 10); FillChar(buf, 10, 0); FillByte(buf, 10, 1); FillWord(buf, 10, 2); FillDWord(buf, 10, 3);
  i := CompareByte(buf, buf, 4); i := CompareChar(buf, buf, 4); i := CompareWord(buf, buf, 4); i := CompareDWord(buf, buf, 4);
  i := IndexByte(buf, 10, 3); i := IndexChar(buf, 10, 'c'); i := IndexWord(buf, 10, 3); i := IndexDWord(buf, 10, 3);
  GetMem(pc, 10); ReallocMem(pc, 20); FreeMem(pc); New(pc); Dispose(pc); i := MemSize(pc);
  r.s := 'a'; r := r; Finalize(r); Initialize(r);
  Halt(0); RunError(1); Exit;
end;
begin
  Main;
end.
"""


def _unit_lists(comp: Compiler, root: Path, lazarus: Path | None) -> tuple[list[str], list[str], list[str]]:
    """(RTL units, LCL units, extra ``-Fu`` folders of the LCL) available for the compiler's target."""
    target = f"{comp.cpu}-{comp.os}"
    units_root = None
    for cand in (root / "units" / target, root.parent / "units" / target, root.parent.parent / "units" / target,
                 root.parent.parent.parent / "units" / target):
        if cand.is_dir():
            units_root = cand
            break
    rtl: list[str] = []
    if units_root is not None:
        for f in _RTL_FOLDERS:
            d = units_root / f
            if d.is_dir():
                rtl += sorted(p.stem for p in d.glob("*.ppu") if not _SKIP_UNIT.match(p.stem))
    lcl: list[str] = []
    folders: list[str] = []
    if lazarus is not None:
        lcl_dir = lazarus / "lcl" / "units" / target
        if lcl_dir.is_dir():
            folders = [str(lcl_dir), str(lcl_dir / "win32"), str(lazarus / "components" / "lazutils" / "lib" / target)]
            lcl = sorted(p.stem for p in lcl_dir.glob("*.ppu")
                         if not re.match(r"^(customdrawn|wslazdeviceapis|lazdeviceapis|alllcl|lcl$|lclbase)", p.stem, re.I))
            lcl += sorted(p.stem for p in (lazarus / "components" / "lazutils" / "lib" / target).glob("*.ppu"))
            lcl = ["Interfaces"] + [u for u in lcl if u.lower() != "interfaces"]
    return sorted(set(rtl), key=str.lower), lcl, folders


def _compile_text(comp: Compiler, text: str, work: Path, name: str) -> Path:
    """Compile the program ``text`` with ``-g``. Returns the executable."""
    work.mkdir(parents=True, exist_ok=True)
    src = work / f"{name}.pas"
    src.write_text(text, encoding="ascii")
    rc, out = _run([str(comp.exe), "-g", "-vewn", f"-FE{work}", f"-FU{work}", str(src)], work)
    exe = work / f"{name}.exe"
    if rc != 0 or not exe.is_file():
        raise FpcError(f"{name} did not compile with {comp.exe.name} {comp.version} {comp.cpu}: "
                       + " | ".join(ln for ln in out.splitlines() if "Error" in ln or "Fatal" in ln)[:600])
    return exe


def _compile(comp: Compiler, units: list[str], work: Path, name: str, folders: list[str],
             say: Callable[[str], None]) -> Path:
    """Compile a program that uses ``units`` with ``-g``; a unit the compiler cannot find is dropped and the
    compile retried. Returns the executable."""
    work.mkdir(parents=True, exist_ok=True)
    units = list(units)
    src = work / f"{name}.pas"
    exe = work / f"{name}.exe"
    for _attempt in range(len(units) + 2):
        src.write_text("program %s;\n{$mode objfpc}{$H+}\nuses\n  %s;\nbegin\nend.\n" % (name, ",\n  ".join(units)),
                       encoding="ascii")
        cmd = [str(comp.exe), "-g", "-vewn", f"-FE{work}", f"-FU{work}"] + [f"-Fu{f}" for f in folders] + [str(src)]
        rc, text = _run(cmd, work)
        if rc == 0 and exe.is_file():
            return exe
        gone = {g.lower() for m in _MISSING.finditer(text) for g in m.groups()}      # the unit and its importer
        gone |= {m.group(1).lower() for m in re.finditer(r"Fatal: Can't find unit (\S+)", text)}
        keep = [u for u in units if u.lower() not in gone]
        if not gone or len(keep) == len(units):
            raise FpcError(f"{name} did not compile with {comp.exe.name} {comp.version} {comp.cpu}: "
                           + " | ".join(ln for ln in text.splitlines() if "Error" in ln or "Fatal" in ln)[:600])
        say(f"{name}: dropped {len(units) - len(keep)} units the compiler cannot find")
        units = keep
    raise FpcError(f"{name}: too many retries")


@dataclass
class BuildResult:
    path: Path
    version: str
    psize: int
    programs: int
    routines: int
    names: int
    seconds: float


def build(compilers: list[Path], out_dir: Path, work: Path, fpc_root: Path | None = None,
          lazarus: Path | None = None, source_dirs: list[Path] | None = None,
          progress: Callable[[str], None] | None = None) -> list[BuildResult]:
    """Build ``fpc-<version>-<bits>.sigdb`` in ``out_dir`` for each compiler (one file per version and
    bitness). ``fpc_root``: the install folder (default: two levels above the compiler, where ``units``
    lives); ``lazarus``: a Lazarus folder whose ``lcl`` adds the LCL; ``source_dirs``: Pascal sources whose
    identifier spelling restores the case of the names."""
    say = progress or (lambda _m: None)
    results: list[BuildResult] = []
    for exe in compilers:
        t0 = time.time()
        comp = probe_compiler(exe)
        root = fpc_root or exe.parent.parent.parent
        rtl, lcl, folders = _unit_lists(comp, root, lazarus)
        if not rtl:
            raise FpcError(f"no RTL units for {comp.cpu}-{comp.os} found near {exe}")
        wdir = work / f"fpc-{comp.version}-{comp.bits}"
        progs: list[Path] = [_compile(comp, rtl, wdir, "rtlmega", [], say)]
        say(f"{comp.version} {comp.bits}-bit: rtlmega ({len(rtl)} units)")
        try:
            progs.append(_compile_text(comp, _TOUCH, wdir, "systouch"))
        except FpcError as e:
            say(f"{comp.version} {comp.bits}-bit: no System program ({e})")
        if lcl:
            try:
                progs.append(_compile(comp, lcl, wdir, "lclmega", folders, say))
                say(f"{comp.version} {comp.bits}-bit: lclmega ({len(lcl)} units)")
            except FpcError as e:
                say(f"{comp.version} {comp.bits}-bit: no LCL program ({e})")
        dirs = tuple(str(d) for d in (source_dirs or _default_sources(root, lazarus)))
        merged: dict[tuple, None] = {}
        psize = 8 if comp.bits == 64 else 4
        for p in progs:
            _ps, recs = scan_exe(str(p), dirs)
            merged.update(dict.fromkeys(recs))
            say(f"{p.name}: {len(recs)} routines")
        records = [r for r in merged if idr.usable(r[2])]
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            vs = collect_vslots(progs, dirs)
            write_names(out_dir, comp.version, vs, guid_names([Path(d) for d in dirs]))
            say(f"{comp.version} {comp.bits}-bit: {sum(len(v) for v in vs.values())} virtual slot names")
        except (OSError, FpcError, ValueError) as e:
            say(f"{comp.version} {comp.bits}-bit: no virtual slot names ({e})")
        path = out_dir / f"fpc-{comp.version}-{comp.bits}.sigdb"
        ds.write_sigdb(path, _compiler_number(comp.version), psize, records,
                       {"toolchain": "fpc", "fpc": comp.version, "built": time.strftime("%Y-%m-%d"),
                        "binaries": len(progs), "format": 3})
        results.append(BuildResult(path, comp.version, psize, len(progs), len({(r[1], r[2]) for r in records}),
                                   len(records), time.time() - t0))
    return results


def _compiler_number(version: str) -> int:
    a = [int(x) for x in re.findall(r"\d+", version)[:3]] + [0, 0, 0]
    return a[0] * 10000 + a[1] * 100 + a[2]


def _default_sources(root: Path, lazarus: Path | None) -> list[Path]:
    out: list[Path] = []
    for base in (root / "source", root.parent / "source", root.parent.parent / "source"):
        if base.is_dir():
            out += [base / "rtl", base / "packages"]
            break
    if lazarus is not None:
        out += [lazarus / "lcl", lazarus / "components" / "lazutils"]
    return [d for d in out if d.is_dir()]


# -- virtual slot and interface names -------------------------------------------------------------

_GUID_DECL = re.compile(r"(\w+)\s*=\s*interface\s*(?:\(\s*\w+\s*\))?\s*\[\s*'(\{[0-9A-Fa-f\-]{36}\})'\s*\]", re.I)
_NO_NAME = re.compile(r"^(fpc_|_?_?fpc_)", re.I)


def vslot_names(exe: Path, cases: CaseMap | None = None) -> dict[str, dict[int, str]]:
    """{class that introduces a virtual slot: {slot: method name}} of the classes of one program that keeps its
    symbols. The method name is the one of the routine the slot holds in the class and in its descendants
    (an override keeps the name); the symbol of the introducing class counts three times, abstract stubs are
    ignored."""
    img = Image.from_pe(exe)
    if img is None:
        return {}
    at: dict[int, tuple[str, str]] = {}                  # address -> (class, method) of its first symbol
    for sym, rva, _x in read_coff(exe):
        nm = display_name(sym, cases)
        if nm is None or _NO_NAME.match(nm.rsplit(".", 1)[-1]) or "." not in nm:
            continue
        parts = nm.split(".")
        at.setdefault(img.base + rva, (parts[-2] if len(parts) > 2 else "", parts[-1]))
    classes = delphi.parse_fpc_classes(img)
    by_vmt = {c.vmt: c for c in classes}
    votes: dict[tuple[str, int], collections.Counter] = collections.defaultdict(collections.Counter)
    for c in classes:
        for m in c.methods:
            if m.kind != "virtual" or m.addr not in at:
                continue
            cur, seen = c, set()
            while cur.vmt not in seen:
                seen.add(cur.vmt)
                up = by_vmt.get(cur.parent_vmt)
                if up is None or up.nvirtual <= m.slot:
                    break
                cur = up
            cls, meth = at[m.addr]
            votes[(cur.name, m.slot)][meth] += 3 if cls.lower() == cur.name.lower() else 1
    out: dict[str, dict[int, str]] = {}
    for (cls, slot), cnt in votes.items():
        out.setdefault(cls, {})[slot] = cnt.most_common(1)[0][0]
    return out


def collect_vslots(programs: list[Path], source_dirs: tuple[str, ...] = ()) -> dict[str, dict[int, str]]:
    """``vslot_names`` of several programs, merged (the first name of a slot wins)."""
    cases = CaseMap()
    for d in source_dirs:
        cases.add_dir(Path(d))
    out: dict[str, dict[int, str]] = {}
    for p in programs:
        for cls, slots in vslot_names(p, cases).items():
            for slot, name in slots.items():
                out.setdefault(cls, {}).setdefault(slot, name)
    return out


def guid_names(source_dirs: list[Path]) -> dict[str, str]:
    """{GUID text: interface name} from the interface declarations in Pascal sources."""
    out: dict[str, str] = {}
    for d in source_dirs:
        try:
            files = [p for p in d.rglob("*") if p.suffix.lower() in _SOURCE_EXT]
        except OSError:
            continue
        for p in files:
            try:
                text = p.read_text(encoding="latin-1")
            except OSError:
                continue
            for m in _GUID_DECL.finditer(text):
                out.setdefault(m.group(2).upper(), m.group(1))
    return out


def names_path(sig_dir: Path, version: str) -> Path:
    return sig_dir / f"fpc-{version}-names.json"


def write_names(sig_dir: Path, version: str, vslots: dict[str, dict[int, str]], guids: dict[str, str]) -> None:
    path = names_path(sig_dir, version)
    data = {"vslots": {c: {str(k): v for k, v in sorted(s.items())} for c, s in sorted(vslots.items())},
            "guids": guids}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def load_names(sig_dir: Path | None, version: str
               ) -> tuple[tuple[dict[str, dict[int, str]], dict[str, str]] | None, str]:
    """((virtual slot names, interface names), tag) of the names file of an FPC version; (None, ``none``) when
    there is none. The tag changes with the file."""
    if sig_dir is None or not version:
        return None, "none"
    path = names_path(sig_dir, version)
    try:
        st = path.stat()
        data = json.loads(path.read_text(encoding="utf-8"))
        vs = {c: {int(k): v for k, v in s.items()} for c, s in data.get("vslots", {}).items()}
        return (vs, {k.upper(): v for k, v in data.get("guids", {}).items()}), f"{st.st_size}:{st.st_mtime_ns}"
    except (OSError, ValueError, AttributeError):
        return None, "none"


# -- database files -----------------------------------------------------------------------------

def sig_files(sig_dir: Path | None, psize: int) -> list[idr.KbFile]:
    """FPC signature databases (``fpc-<version>-<32|64>.sigdb``) of the pointer size; ``KbFile.year`` is the
    FPC version."""
    out: list[idr.KbFile] = []
    try:
        names = sorted(sig_dir.iterdir()) if sig_dir is not None else []
    except OSError:
        return []
    for p in names:
        m = FPC_SIG_NAME.match(p.name)
        if not m or int(m.group(2)) != psize * 8:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        if p.is_file() and st.st_size > 64:
            out.append(idr.KbFile(p, f"fpc{m.group(1)}-{m.group(2)}", m.group(1), True, st.st_size, True))
    return out


# -- oracle -------------------------------------------------------------------------------------

def measure(exe: Path, sigdir: Path, own_units: set[str] | None = None) -> "OracleResult":
    """Name the routines of an FPC program that keeps its COFF symbols with the database of its version and
    compare with the symbols. ``own_units``: units that are the program's own code (default: the program
    unit, found as the unit of ``main`` / ``PASCALMAIN`` and the ``P$`` prefix); other routines are library
    routines."""
    from airlock.server import delphioracle as do
    from airlock.server.cpp import Image
    from airlock.projects import FPC_VERSION_RE

    img = Image.from_pe(exe)
    if img is None:
        raise FpcError(f"{exe} is not a PE file")
    version = None
    for s in img.sections:
        m = FPC_VERSION_RE.search(s.data)
        if m:
            version = m.group(1).decode() if isinstance(m.group(1), bytes) else m.group(1)
            break
    files = [f for f in sig_files(sigdir, img.psize) if f.year == version]
    if not files:
        raise FpcError(f"no FPC signature database for {version}, {img.psize * 8}-bit in {sigdir}")
    syms = read_coff(exe)
    if not syms:
        raise FpcError(f"{exe.name} has no symbol table: build it with -g")
    by_rva: dict[int, list[tuple[str, str]]] = {}
    own = {u.lower() for u in (own_units or set())}
    for sym, rva, _x in syms:
        if sym.startswith("P$"):
            own.add(sym[2:].split("_$$_", 1)[0].split("$_$", 1)[0].lower())
    starts = sorted({rva for _s, rva, _x in syms})
    info: dict[int, tuple[list[str], str, int | None]] = {}
    funcs: list[tuple[int, int | None]] = []
    for sym, rva, _x in syms:
        nm = display_name(sym)
        if nm is None:
            continue
        unit = nm.split(".", 1)[0].lower() if "." in nm else ""
        by_rva.setdefault(rva, []).append((nm, unit))
    for rva, lst in sorted(by_rva.items()):
        j = bisect.bisect_right(starts, rva)
        size = (starts[j] - rva) if j < len(starts) else None
        a = img.base + rva
        names = [n for n, _u in lst]
        info[a] = (names, lst[0][1], size)
        funcs.append((a, size))
    lib = [a for a in info if info[a][1] not in own]
    kb = idr.load_kb(files[0])
    code_hits, ctx = idr.match_with_context(kb, img, funcs)
    with_ctx = {**ctx, **code_hits}
    res = do.OracleResult(_compiler_number(version or "0"), img.psize * 8, len(kb.procs), len(funcs), len(lib), 0,
                          len(funcs) - len(lib))
    prev: dict[int, list[str]] = {}
    for label, hits in (("sigdb", code_hits), ("+calls", with_ctx)):
        st = do.Stage(label)
        for a in lib:
            truth, _m, sz = info[a]
            do.score(hits.get(a), truth, st.all)
            if sz is not None and sz >= do.MIN_BIG:
                do.score(hits.get(a), truth, st.big)
            if a in hits and a not in prev:
                do.score(hits.get(a), truth, st.added)
        res.stages.append(st)
        prev = hits
    libs = set(lib)
    res.own_named = sum(1 for a in info if a not in libs and a in with_ctx)
    return res
