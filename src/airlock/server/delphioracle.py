"""Oracle measurement of the signature databases (DESIGN 11 "Delphi", "Oracle").

A Delphi program built with ``-GD`` has a detailed map file: the true name and bounds of every routine. The
measurement names the routines of the binary with the installed exact-version database (the same matcher the
analysis uses, ``idr.match_all``) and compares with the map. Routines of units that are not in ``own`` are
*library* routines; a database can only know those. ``right`` = a returned name equals the map name (generic
arguments ignored: ``TList<X>.Add`` equals ``TList<T>.Add``), ``exact`` = the same without ignoring them,
``wrong`` = a name that differs, ``none`` = no name. Counted for all routines and for those of at least
``MIN_BIG`` bytes.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path

from airlock.server import delphimap as dm, idr
from airlock.server.cpp import Image

MIN_BIG = 24


class OracleError(RuntimeError):
    """The measurement cannot be made."""


@dataclass
class Counts:
    n: int = 0
    right: int = 0
    exact: int = 0
    wrong: int = 0
    none: int = 0


@dataclass
class OracleResult:
    compiler: int
    bits: int
    sigdb_names: int
    routines: int
    library: int
    own_named: int
    own_total: int
    all: Counts = field(default_factory=Counts)
    big: Counts = field(default_factory=Counts)


def norm(n: str) -> str:
    """Lower case, generic arguments dropped: ``TList<X>.Add`` -> ``tlist<>.add``."""
    out, d = [], 0
    for ch in n.lower():
        if ch == "<":
            if d == 0:
                out.append("<>")
            d += 1
        elif ch == ">":
            d = max(0, d - 1)
        elif d == 0:
            out.append(ch)
    return "".join(out)


def score(got: list[str] | None, truth: list[str], c: Counts) -> None:
    """Count one routine: ``got`` = names the matcher returned (best first), ``truth`` = names in the map."""
    c.n += 1
    if not got:
        c.none += 1
        return
    tl = {norm(t) for t in truth}
    if any(norm(g) in tl for g in got[:3]):
        c.right += 1
        low = {t.lower() for t in truth}
        if any(g.lower() in low for g in got[:3]):
            c.exact += 1
    else:
        c.wrong += 1


def measure(exe: Path, mp: Path, sigdir: Path, own_dir: Path | None = None) -> OracleResult:
    own = {p.stem.lower() for p in (own_dir or exe.parent).glob("*.dcu")} | {exe.stem.lower()}
    pimg, named, starts = dm.map_routines(exe, mp)
    mf = dm.parse_map(mp.read_text(encoding="latin-1", errors="replace"))
    rvas = dm.section_rvas(pimg, mf.segments, dm.pe_section_names(exe), pimg.image_base)
    mods = sorted((rvas[s] + o, rvas[s] + o + ln, m) for s, o, ln, m in mf.modules if s in rvas)
    mstart = [m[0] for m in mods]
    srt = sorted(starts)
    img = Image.from_pe(exe)
    comp = idr.compiler_version(img)
    files = [f for f in idr.sig_files(sigdir, img.psize) if f.sig and not f.rtti and int(f.year) == comp]
    if not files:
        raise OracleError(f"no signature database for compiler {comp}, {img.psize * 8}-bit in {sigdir}")
    kb = idr.load_kb(files[0])

    def module(rva: int):
        i = bisect.bisect_right(mstart, rva) - 1
        if i >= 0 and rva < mods[i][1]:
            return mods[i][2], mods[i][1]
        return None, None

    funcs, info = [], {}
    for rva in sorted(named):
        j = bisect.bisect_right(srt, rva)
        nxt = srt[j] if j < len(srt) else rva + 16
        m, mend = module(rva)
        size = min(nxt, mend or nxt) - rva
        if size <= 0:
            size = None
        funcs.append((img.base + rva, size))
        info[img.base + rva] = (named[rva], m, size)
    hits = idr.match_all(kb, img, funcs)
    lib = [a for a in info if (info[a][1] or "").lower() not in own]
    res = OracleResult(comp, img.psize * 8, len(kb.procs), len(funcs), len(lib), 0, len(funcs) - len(lib))
    for a in lib:
        truth, _m, sz = info[a]
        score(hits.get(a), truth, res.all)
        if sz is not None and sz >= MIN_BIG:
            score(hits.get(a), truth, res.big)
    libs = set(lib)
    res.own_named = sum(1 for a in info if a not in libs and a in hits)
    return res


def format_result(r: OracleResult) -> str:
    def row(tag: str, c: Counts) -> str:
        d = max(1, c.n)
        return (f"{tag}: {c.n} routines, right {c.right} ({100 * c.right / d:.1f}%), exact {c.exact} "
                f"({100 * c.exact / d:.1f}%), wrong {c.wrong} ({100 * c.wrong / d:.1f}%), none {c.none} "
                f"({100 * c.none / d:.1f}%)")

    return "\n".join([
        f"compiler {r.compiler}, {r.bits}-bit, {r.sigdb_names} database names, {r.routines} map routines, "
        f"{r.library} library ({100 * r.library / max(1, r.routines):.1f}%)",
        row("all", r.all),
        row(f">={MIN_BIG} bytes", r.big),
        f"own code named: {r.own_named} of {r.own_total}"])
