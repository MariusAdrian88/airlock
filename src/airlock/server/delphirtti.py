"""Consensus names for Delphi RTL / VCL routines, learned from the extended RTTI of many programs
(DESIGN 11 "Delphi", "RTTI consensus database").

Since Delphi 2010 the RTTI of a class names its methods with their code addresses (``delphi._rtti_methods``).
A program that links the RTL statically therefore names thousands of RTL and VCL routines itself. This module
reads those names from many unrelated Delphi programs, takes the masked code bytes at each named address
(``delphisigs._scan_routine``: relocations, ``rel32`` operands outside the routine and absolute addresses are
masked) and keeps a (code shape, name) pair only where several independent files agree. The idea is the
"extended RTTI consensus" of psifertex/delphinja (MIT, see THIRD_PARTY_NOTICES); the code here is new.

* Only classes of runtime units go in (``System.*``, ``Vcl.*``, ``Winapi.*``, ``Data.*`` ...). Program
  classes never do: they are the code of the target, and their names would leak between products.
* A name needs ``min_binaries`` distinct files (identical files count once) and ``min_products`` distinct
  products (one product = one folder given to the command). A shape that carries more than ``MAX_ALIASES``
  names is a stub (``ret``, a wrapper around one call) and is dropped.
* Generic instances are stored as ``TList<T>.Add``: type arguments are program types.
* Output: ``rtti-<compiler>-<32|64>.sigdb``, the sigdb file format (``delphisigs.write_sigdb``), loaded after the
  exact-version database and before the IDR knowledge bases (``idr._pick``). Derived data: never committed.
"""

from __future__ import annotations

import bisect
import hashlib
import logging
import re
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from airlock.server import delphi, delphisigs, idr
from airlock.server.cpp import Image

log = logging.getLogger("airlock")

RTTI_NAME = re.compile(r"^rtti-(\d+)-(32|64)\.sigdb$")
MAX_ALIASES = 6                      # names one code shape may carry
MIN_BINARIES = 3
MAX_FILE = 400_000_000
_EXT = {".exe", ".dll", ".bpl", ".dpl", ".ocx", ".cpl", ".ax", ".scr", ".sys", ".drv", ".tlb", ".dbk", ".hdl"}
_INDY = re.compile(r"^Id[A-Z]\w*(\.\w+)*$")
_GENERIC = re.compile(r"<[^<>]*>")


class RttiError(ValueError):
    """The database cannot be built."""


# -- names ---------------------------------------------------------------------------------------

def allowed_unit(unit: str, indy: bool = False) -> bool:
    """True for a unit of the runtime library (the classes whose names may enter the database)."""
    if not unit:
        return False
    return delphi.runtime_unit(unit) or (indy and bool(_INDY.match(unit)))


def normalize_class(name: str) -> str:
    """``TList<System.Foo.TBar>.TEnumerator`` -> ``TList<T>.TEnumerator`` (type arguments are program types)."""
    prev = None
    while prev != name:
        prev = name
        name = _GENERIC.sub("\0", name)
    if "<" in name or ">" in name:           # a ShortString cut at 255 characters leaves an open bracket
        head = re.split(r"[<>]", name, maxsplit=1)[0]
        return head.replace("\0", "<T>") + "<T>"
    return name.replace("\0", "<T>")


def routine_name(unit: str, cls: str, method: str) -> str:
    return f"{unit}.{normalize_class(cls)}.{method}"


# -- scanning one binary ------------------------------------------------------------------------

@dataclass
class Scanned:
    sha: bytes                                   # first 12 bytes of the SHA-256 of the file
    compiler: int
    psize: int
    records: list[tuple[str, bytes, bytes]]      # (name, dump, mask)
    classes: int = 0
    methods: int = 0                              # runtime methods with RTTI names


def candidate_files(folder: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(folder.rglob("*")):
        try:
            if p.suffix.lower() in _EXT and p.is_file() and 4096 < p.stat().st_size <= MAX_FILE:
                out.append(p)
        except OSError:
            continue
    return out


def scan_binary(path_str: str, indy: bool = False) -> Scanned | None:
    """RTTI-named runtime routines of one binary, or None when it is not a Delphi program that links the RTL
    statically (no compiler string) or has no extended RTTI. Runs in worker processes."""
    try:
        import capstone
    except ImportError as e:                                    # pragma: no cover
        raise delphisigs.SigError("the build needs the capstone package (pip install capstone)") from e
    path = Path(path_str)
    raw = path.read_bytes()
    m = idr._COMPILER.search(raw)
    if m is None:
        return None
    comp = int(m.group(1))
    sha = hashlib.sha256(raw).digest()[:12]
    del raw
    img = Image.from_pe(path)
    if img is None:
        return None
    classes = delphi.parse_classes(img)
    wanted: list[tuple[str, int]] = []
    starts: set[int] = set()
    for c in classes:
        runtime = allowed_unit(c.unit, indy)
        for mt in c.methods:
            starts.add(mt.addr)
            if runtime and mt.kind.startswith("rtti"):
                wanted.append((routine_name(c.unit, c.name, mt.name), mt.addr))
    if not wanted:
        return Scanned(sha, comp, img.psize, [], len(classes), 0)
    pe = delphisigs._read_pe(path)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if pe.psize == 8 else capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = False
    base = pe.image_base
    top = max(va + max(vs, rs) for va, vs, _r, rs, _x in pe.sections)
    srt = sorted(a - base for a in starts)
    funcs = pe.funcs
    by_addr: dict[int, set[str]] = defaultdict(set)
    for name, addr in wanted:
        by_addr[addr].add(name)
    out: list[tuple[str, bytes, bytes]] = []
    for addr in sorted(by_addr):
        rva = addr - base
        i = bisect.bisect_right(srt, rva)
        limit = (srt[i] - rva) if i < len(srt) else delphisigs.MAX_SWEEP
        exact = funcs[rva] - rva if funcs and rva in funcs else None
        try:
            got = delphisigs._scan_routine(md, pe, rva, max(limit, 1), exact, (base, base + top))
        except Exception as e:  # noqa: BLE001  one bad routine must not lose the binary
            log.debug("rtti scan %s at %x: %s", path.name, addr, e)
            continue
        if got is None:
            continue
        for name in sorted(by_addr[addr]):
            out.append((name, got[0], got[1]))
    return Scanned(sha, comp, img.psize, out, len(classes), len(wanted))


# -- voting ---------------------------------------------------------------------------------------

@dataclass
class Group:
    """Votes for one (compiler, pointer size)."""
    shapes: dict[bytes, tuple[bytes, bytes]] = field(default_factory=dict)
    files: dict[bytes, dict[str, set[bytes]]] = field(default_factory=dict)       # shape -> name -> file ids
    prods: dict[bytes, dict[str, set[int]]] = field(default_factory=dict)         # shape -> name -> products
    seen: set[bytes] = field(default_factory=set)
    by_product: dict[int, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, s: Scanned, product: int) -> bool:
        """Count one binary; False when an identical file was counted before."""
        if s.sha in self.seen:
            return False
        self.seen.add(s.sha)
        self.by_product[product] += 1
        for name, dump, mask in s.records:
            key = hashlib.blake2b(dump + b"\xff" + mask, digest_size=12).digest()
            self.shapes.setdefault(key, (dump, mask))
            self.files.setdefault(key, {}).setdefault(name, set()).add(s.sha)
            self.prods.setdefault(key, {}).setdefault(name, set()).add(product)
        return True


@dataclass
class Selection:
    records: list[tuple[str, bytes, bytes]]
    shapes: int = 0
    cross_product: int = 0           # names agreed by two or more products
    single_product: int = 0
    stubs: int = 0                   # shapes dropped for carrying too many names
    weak: int = 0                    # names seen but without enough votes


def select(g: Group, min_binaries: int = MIN_BINARIES, min_products: int = 1,
           max_aliases: int = MAX_ALIASES) -> Selection:
    sel = Selection([])
    for key, names in g.files.items():
        keep = [n for n, f in names.items() if len(f) >= min_binaries and len(g.prods[key][n]) >= min_products]
        sel.weak += len(names) - len(keep)
        if not keep:
            continue
        if len(keep) > max_aliases:
            sel.stubs += 1
            continue
        dump, mask = g.shapes[key]
        sel.shapes += 1
        for n in sorted(keep):
            sel.records.append((n, dump, mask))
            if len(g.prods[key][n]) >= 2:
                sel.cross_product += 1
            else:
                sel.single_product += 1
    return sel


# -- build ------------------------------------------------------------------------------------------

@dataclass
class RttiResult:
    path: Path
    compiler: int
    psize: int
    binaries: int                      # distinct files counted
    names: int
    shapes: int
    cross_product: int
    single_product: int
    stubs: int
    seconds: float = 0.0


def _sha_file(p: Path) -> bytes:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.digest()[:12]


def build(folders: list[Path], out_dir: Path, min_binaries: int = MIN_BINARIES, min_products: int = 1,
          jobs: int = 4, exclude: list[Path] | None = None, indy: bool = False,
          progress: Callable[[str], None] | None = None) -> list[RttiResult]:
    """Scan the Delphi binaries under ``folders`` (one product each), vote, and write one database per
    (compiler, pointer size) to ``out_dir``. ``exclude``: files to leave out (and files identical to them)."""
    t0 = time.time()
    say = progress or (lambda _m: None)
    if not folders:
        raise RttiError("give at least one folder with Delphi programs")
    skip: set[bytes] = set()
    for p in exclude or []:
        try:
            skip.add(_sha_file(p))
        except OSError as e:
            raise RttiError(f"cannot read the excluded file {p}: {e.strerror or e}") from e
    jobs_list: list[tuple[int, Path]] = []
    for pi, folder in enumerate(folders):
        if not folder.is_dir():
            raise RttiError(f"{folder} is not a folder")
        jobs_list.extend((pi, f) for f in candidate_files(folder))
    say(f"{len(jobs_list)} candidate files in {len(folders)} folders")
    groups: dict[tuple[int, int], Group] = {}
    done = 0

    def take(pi: int, path: Path, s: Scanned | None) -> None:
        nonlocal done
        if s is None or s.sha in skip:
            return
        g = groups.setdefault((s.compiler, s.psize), Group())
        if g.add(s, pi):
            done += 1
            say(f"{path.name}: {s.methods} runtime methods, {len(s.records)} routines")

    if jobs > 1 and len(jobs_list) > 1:
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            futs = [(pi, p, ex.submit(scan_binary, str(p), indy)) for pi, p in jobs_list]
            for pi, p, fut in futs:
                try:
                    take(pi, p, fut.result())
                except Exception as e:  # noqa: BLE001
                    say(f"{p.name}: skipped ({e})")
    else:
        for pi, p in jobs_list:
            try:
                take(pi, p, scan_binary(str(p), indy))
            except Exception as e:  # noqa: BLE001
                say(f"{p.name}: skipped ({e})")
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[RttiResult] = []
    for (comp, psize), g in sorted(groups.items()):
        sel = select(g, min_binaries, min_products)
        if not sel.records:
            say(f"compiler {comp} {psize * 8}-bit: {len(g.seen)} binaries, no name has enough votes")
            continue
        path = out_dir / f"rtti-{comp}-{psize * 8}.sigdb"
        delphisigs.write_sigdb(path, comp, psize, sel.records,
                               {"kind": "rtti", "binaries": len(g.seen), "products": len(g.by_product),
                                "min_binaries": min_binaries, "min_products": min_products,
                                "built": time.strftime("%Y-%m-%d"), "format": 2})
        results.append(RttiResult(path, comp, psize, len(g.seen), len(sel.records), sel.shapes,
                                  sel.cross_product, sel.single_product, sel.stubs, time.time() - t0))
    return results
