"""Oracle measurement of the signature databases (DESIGN 11 "Delphi", "Oracle").

A Delphi program built with ``-GD`` has a detailed map file: the true name and bounds of every routine. The
measurement names the routines of the binary with the installed exact-version database (the same matcher the
analysis uses, ``idr.match_all``) and compares with the map. Routines of units that are not in ``own`` are
*library* routines; a database can only know those. ``right`` = a returned name equals the map name (generic
arguments ignored: ``TList<X>.Add`` equals ``TList<T>.Add``), ``exact`` = the same without ignoring them,
``wrong`` = a name that differs, ``none`` = no name. Counted for all routines and for those of at least
``MIN_BIG`` bytes. The measurement runs the passes in the order of the analysis and reports each stage: the
database by code (``sigdb``), plus the call-context pass (``idr.call_context``), plus the property accessors
(``delphi.accessor_names``, named ``Class.GetProp`` by convention).
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path

from airlock.server import delphi, delphimap as dm, idr
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
class Stage:
    label: str
    all: Counts = field(default_factory=Counts)
    big: Counts = field(default_factory=Counts)
    added: Counts = field(default_factory=Counts)      # routines this stage named (library routines only)


@dataclass
class OracleResult:
    compiler: int
    bits: int
    sigdb_names: int
    routines: int
    library: int
    own_named: int
    own_total: int
    stages: list[Stage] = field(default_factory=list)

    @property
    def all(self) -> Counts:
        return self.stages[0].all

    @property
    def big(self) -> Counts:
        return self.stages[0].big


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


def _truth(exe: Path, mp: Path, own_dir: Path | None):
    """(image, compiler, funcs, info, library routines) of a program and its map: ``funcs`` are (address, size)
    of every map routine, ``info[address]`` = (names, module, size)."""
    own = {p.stem.lower() for p in (own_dir or exe.parent).glob("*.dcu")} | {exe.stem.lower()}
    pimg, named, starts = dm.map_routines(exe, mp)
    mf = dm.parse_map(mp.read_text(encoding="latin-1", errors="replace"))
    rvas = dm.section_rvas(pimg, mf.segments, dm.pe_section_names(exe), pimg.image_base)
    mods = sorted((rvas[s] + o, rvas[s] + o + ln, m) for s, o, ln, m in mf.modules if s in rvas)
    mstart = [m[0] for m in mods]
    srt = sorted(starts)
    img = Image.from_pe(exe)
    comp = idr.compiler_version(img)

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
    lib = [a for a in info if (info[a][1] or "").lower() not in own]
    return img, comp, funcs, info, lib


def measure_foreign(exe: Path, mp: Path, sigdir: Path, warp_dir: Path | None, own_dir: Path | None = None
                    ) -> OracleResult:
    """Leave-one-out measurement: the program's own compiler version is treated as one without databases. The
    exact-version signature database (and RTTI database) of that compiler is hidden; the stages are the other
    signature databases through the analysis' tier chain (``idr._pick``) without and with the WARP libraries of
    ``warp_dir``. Counts are for library routines."""
    img, comp, funcs, info, lib = _truth(exe, mp, own_dir)
    sigs = [f for f in idr.kb_files(None, img.psize, sigdir) if not (comp is not None and int(f.year) == comp)]
    wfiles = idr.warp_files(warp_dir, img.psize)
    res = OracleResult(comp or 0, img.psize * 8, len(sigs), len(funcs), len(lib), 0, len(funcs) - len(lib))
    prev: dict[int, list[str]] = {}
    for label, files in (("other versions", sigs), ("+warp", sigs + wfiles)):
        _l, hits, _n = idr._pick(files, img, funcs)
        st = Stage(label)
        for a in lib:
            truth, _m, sz = info[a]
            score(hits.get(a), truth, st.all)
            if sz is not None and sz >= MIN_BIG:
                score(hits.get(a), truth, st.big)
            if a in hits and a not in prev:
                score(hits.get(a), truth, st.added)
        res.stages.append(st)
        prev = hits
    return res


def measure(exe: Path, mp: Path, sigdir: Path, own_dir: Path | None = None) -> OracleResult:
    img, comp, funcs, info, lib = _truth(exe, mp, own_dir)
    files = [f for f in idr.sig_files(sigdir, img.psize) if f.sig and not f.rtti and int(f.year) == comp]
    if not files:
        raise OracleError(f"no signature database for compiler {comp}, {img.psize * 8}-bit in {sigdir}")
    kb = idr.load_kb(files[0])
    code_hits, ctx = idr.match_with_context(kb, img, funcs)
    with_ctx = {**ctx, **code_hits}
    props = {a: [n] for a, n in delphi.accessor_names(delphi.parse_classes(img)).items()
             if a in info and a not in with_ctx}
    with_props = {**props, **with_ctx}
    res = OracleResult(comp, img.psize * 8, len(kb.procs), len(funcs), len(lib), 0, len(funcs) - len(lib))
    prev: dict[int, list[str]] = {}
    for label, hits in (("sigdb", code_hits), ("+calls", with_ctx), ("+props", with_props)):
        st = Stage(label)
        for a in lib:
            truth, _m, sz = info[a]
            score(hits.get(a), truth, st.all)
            if sz is not None and sz >= MIN_BIG:
                score(hits.get(a), truth, st.big)
            if a in hits and a not in prev:
                score(hits.get(a), truth, st.added)
        res.stages.append(st)
        prev = hits
    libs = set(lib)
    res.own_named = sum(1 for a in info if a not in libs and a in with_props)
    return res


def format_result(r: OracleResult) -> str:
    def row(tag: str, c: Counts) -> str:
        d = max(1, c.n)
        return (f"{tag}: {c.n} routines, right {c.right} ({100 * c.right / d:.1f}%), exact {c.exact} "
                f"({100 * c.exact / d:.1f}%), wrong {c.wrong} ({100 * c.wrong / d:.1f}%), none {c.none} "
                f"({100 * c.none / d:.1f}%)")

    lines = [f"compiler {r.compiler}, {r.bits}-bit, {r.sigdb_names} database names, {r.routines} map routines, "
             f"{r.library} library ({100 * r.library / max(1, r.routines):.1f}%)"]
    for st in r.stages:
        lines += [row(f"[{st.label}] all", st.all), row(f"[{st.label}] >={MIN_BIG} bytes", st.big)]
        if st is not r.stages[0]:
            lines.append(row(f"[{st.label}] newly named", st.added))
    lines.append(f"own code named: {r.own_named} of {r.own_total}")
    return "\n".join(lines)
