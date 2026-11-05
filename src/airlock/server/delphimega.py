"""A package of every compiled unit of a Delphi install, with a detailed map (DESIGN 11 "Delphi",
"Signature databases from map files").

The compiled units of a Delphi install (``lib\\win32\\release``, ``lib\\win64\\release``: one ``.dcu`` per unit)
hold the machine code that a program links statically. This module writes a package project that *contains* all
of them, builds it with the install's own compiler (``dcc32`` / ``dcc64``) and the detailed map option
(``-GD``), and leaves the package binary and its map file in a work folder. A package has no smart linking:
every routine of every contained unit ends up in the binary and in the map, private and nested routines and
unexported generic instances included. ``delphimap`` turns the pair into signatures.

Nothing in the install is changed: the compiler reads the ``.dcu`` files only and every output goes to the work
folder. No source code is read or needed.

One package holds only so many exports (``E2621``: the export table exceeds 65536 entries), so the units are
split along the packages the install ships. Each shipped ``.bpl`` names its units and its required packages in
its ``PACKAGEINFO`` resource, and the matching ``.dcp`` files sit next to the ``.dcu`` files. The build makes one
package per shipped package (same units, ``requires`` the shipped ``.dcp`` of the same packages, so no unit is
linked twice) and one more package for the units that no shipped package holds, which requires all of them. Each
shipped package is under the limit by construction. The packages are independent and build in parallel.

Some units cannot be part of the package (a missing resource file that the install does not ship, a unit of a
product that is not installed). The compiler names the problem; the unit is left out and the build repeats. The
leftovers are listed in the result.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

NAMESPACES = "Winapi;System.Win;Data.Win;Datasnap.Win;Web.Win;Soap.Win;Xml.Win"
MAX_ROUNDS = 60
SKIP_UNITS = {"system", "sysinit"}                       # always part of a package
_USED_BY = re.compile(r"Unit '([^']+)' is used by '([^']+)'")
_MISSING_FILE = re.compile(r"E1026 File not found: '([^']+)'")
_UNIT_ERR = re.compile(r"([\w.]+)\.(?:pas|dcu)\(\d+\) (?:Fatal|Error)")
_DENIED = re.compile(r"E2223 \$DENYPACKAGEUNIT '([^']+)'")


class MegaError(RuntimeError):
    """The package could not be built."""


@dataclass
class MegaResult:
    pairs: list[tuple[Path, Path]]            # (package binary, map file) of every package that was built
    psize: int
    units: int
    excluded: list[str] = field(default_factory=list)
    rounds: int = 0
    seconds: float = 0.0
    failed: list[str] = field(default_factory=list)      # packages that could not be built, with the reason


@dataclass
class Part:
    """One package of the build: its units and the shipped packages (``.dcp`` stems) it requires."""
    name: str
    units: list[str]
    requires: list[str] = field(default_factory=list)


@contextlib.contextmanager
def work_lock(work: Path):
    """Own a work folder for the length of a run. Two runs on one folder wipe each other's packages (a run
    deletes the folder when it starts and again when it ends; the maps are read long after the compiler wrote
    them), which surfaces as a ``FileNotFoundError`` on a map. The lock is an OS file lock on ``<work>.lock``:
    it goes away with a crashed process. Raises MegaError when another run holds it."""
    work.parent.mkdir(parents=True, exist_ok=True)
    path = work.with_name(work.name + ".lock")
    f = open(path, "a+b")
    try:
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        f.close()
        raise MegaError(f"the work folder {work} is in use by another run (lock {path.name}); "
                        f"wait for it or use another --work folder") from e
    try:
        yield
    finally:
        try:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        f.close()
        with contextlib.suppress(OSError):
            path.unlink()


def compiler_exe(install: Path, psize: int) -> Path:
    return install / "bin" / ("dcc64.exe" if psize == 8 else "dcc32.exe")


def lib_dir(install: Path, psize: int) -> Path:
    return install / "lib" / ("win64" if psize == 8 else "win32") / "release"


def unit_names(lib: Path) -> list[str]:
    """Names of the compiled units in a ``lib`` folder, sorted (the file name is the unit name)."""
    try:
        return sorted(p.stem for p in lib.iterdir() if p.suffix.lower() == ".dcu" and p.stem.lower() not in SKIP_UNITS)
    except OSError:
        return []


def dpk_text(name: str, units: list[str], requires: list[str] | None = None) -> str:
    req = "requires\n  " + ",\n  ".join(requires) + ";\n" if requires else ""
    return (f"package {name};\n{{$RUNONLY}}\n{{$IMPLICITBUILD OFF}}\n{req}contains\n  "
            + ",\n  ".join(units) + ";\nend.\n")


def write_project(work: Path, lib: Path, units: list[str], psize: int, resource_dirs: list[Path],
                  name: str = "mega", requires: list[str] | None = None) -> None:
    """``<name>.dpk`` (requires and contains clauses) and ``<name>.cfg`` (compiler switches, read next to the
    project)."""
    (work / "dcu").mkdir(parents=True, exist_ok=True)
    (work / "bpl").mkdir(parents=True, exist_ok=True)
    (work / "dcp").mkdir(parents=True, exist_ok=True)
    (work / f"{name}.dpk").write_text(dpk_text(name, units, requires), encoding="latin-1")
    ns = NAMESPACES + (";Bde" if psize == 4 else "")
    cfg = ["-B", "-GD", "-Q", "-W-", "-H-", f"-NS{ns}", f"-LE{work / 'bpl'}", f"-LN{work / 'dcp'}",
           f"-N0{work / 'dcu'}", f"-NU{work / 'dcu'}", f"-E{work / 'bpl'}",
           f'-U"{lib}"', f'-I"{lib}"', f'-R"{lib}"']
    cfg += [f'-R"{d}"' for d in resource_dirs]
    (work / f"{name}.cfg").write_text("\n".join(cfg) + "\n", encoding="latin-1")


def parse_package_info(data: bytes) -> tuple[list[str], list[str]]:
    """(required packages, contained units) from a ``PACKAGEINFO`` resource. Layout: flags (4 bytes), the number
    of required packages (4), those (hash byte, name, 0), the number of units (4), those (flags byte, hash byte,
    name, 0). Raises ValueError on a truncated resource."""
    try:
        nreq = struct.unpack_from("<II", data, 0)[1]
        p = 8
        req: list[str] = []
        for _ in range(nreq):
            e = data.index(0, p + 1)
            req.append(data[p + 1:e].decode("latin-1"))
            p = e + 1
        nun = struct.unpack_from("<I", data, p)[0]
        p += 4
        units: list[str] = []
        for _ in range(nun):
            e = data.index(0, p + 2)
            units.append(data[p + 2:e].decode("latin-1"))
            p = e + 1
    except (struct.error, ValueError) as e:
        raise ValueError(f"bad PACKAGEINFO: {e}") from e
    return req, units


def read_package_info(path: Path) -> tuple[list[str], list[str]] | None:
    """Required packages and contained units of a ``.bpl``, or None when it has no readable PACKAGEINFO."""
    import pefile
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if t.id != 10:                                                  # RT_RCDATA
                continue
            for n in t.directory.entries:
                if n.name and str(n.name).upper() == "PACKAGEINFO":
                    e = n.directory.entries[0]
                    e = e.directory.entries[0] if hasattr(e, "directory") else e
                    d = e.data.struct
                    return parse_package_info(pe.get_data(d.OffsetToData, d.Size))
    except (OSError, ValueError, AttributeError, IndexError, pefile.PEFormatError):
        return None
    return None


def shipped_packages(install: Path, psize: int) -> list[Path]:
    """The ``.bpl`` files of the install for a platform: ``Redist\\win32|win64`` and ``bin`` / ``bin64``."""
    sub, extra = ("win64", "bin64") if psize == 8 else ("win32", "bin")
    found: dict[str, Path] = {}
    for folder in (install / "Redist" / sub, install / extra):
        try:
            for p in sorted(folder.glob("*.bpl")):
                found.setdefault(p.name.lower(), p)
        except OSError:
            continue
    return list(found.values())


def dcp_stem(required: str, dcps: dict[str, str]) -> str | None:
    """The ``.dcp`` stem for a package name as the resource spells it (``rtl260.bpl``): the shipped ``.dcp``
    files have no version number. ``dcps`` maps lower case stem -> stem."""
    base = re.sub(r"\.bpl$", "", required, flags=re.I)
    for cand in (base, re.sub(r"\d{2,3}$", "", base)):
        if cand.lower() in dcps:
            return dcps[cand.lower()]
    return None


def plan_parts(infos: dict[str, tuple[list[str], list[str]]], units: list[str], dcps: dict[str, str],
               runtime: set[str] | None = None) -> list[Part]:
    """Packages of the build from the shipped ones. ``infos``: package file name -> (required, contained).
    A shipped package is used when it and all packages it requires have a ``.dcp``; the units of the others go to
    the last package. A unit a required package holds is dropped from a package (it would be linked twice). The
    last package holds the units that no used package holds and requires every used runtime package (``runtime``:
    file names; the default is all used packages; a design-time package can require packages the install does not
    ship, in its ``.dcp``)."""
    have = {u.lower(): u for u in units}
    by_stem: dict[str, str] = {}              # dcp stem (lower) -> package file name
    reqs: dict[str, list[str]] = {}           # used package file name -> required dcp stems
    for fn, (req, _u) in infos.items():
        st = dcp_stem(fn, dcps)
        stems = [dcp_stem(r, dcps) for r in req]
        if st and all(stems):
            by_stem[st.lower()] = fn
            reqs[fn] = [x for x in stems if x]

    def closure(fn: str) -> set[str]:
        seen: set[str] = set()
        todo = [fn]
        while todo:
            for st in reqs.get(todo.pop(), []):
                nxt = by_stem.get(st.lower())
                if nxt and nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
        return seen

    parts: list[Part] = []
    covered: set[str] = set()
    for fn in sorted(reqs, key=str.lower):
        above: set[str] = set()
        for o in closure(fn):
            above |= {u.lower() for u in infos[o][1]}
        mine: list[str] = []
        for u in infos[fn][1]:
            k = u.lower()
            if k in have and k not in above and have[k] not in mine:
                mine.append(have[k])
        covered |= {u.lower() for u in infos[fn][1]}
        if mine:
            parts.append(Part(re.sub(r"\W", "_", re.sub(r"\.bpl$", "", fn, flags=re.I)), mine, reqs[fn]))
    rest = [u for u in units if u.lower() not in covered]
    if rest or not parts:
        own = sorted({dcp_stem(fn, dcps) or "" for fn in reqs if runtime is None or fn in runtime} - {""},
                     key=str.lower)
        parts.append(Part("rest", rest or list(units), own if rest else []))
    return parts


def resource_folders(install: Path) -> list[Path]:
    """Folders under ``source`` that hold resource files some unit refers to by name (``$R`` clauses)."""
    out: set[Path] = set()
    src = install / "source"
    if not src.is_dir():
        return []
    for p in src.rglob("*"):
        if p.suffix.lower() in (".res", ".dfm", ".fmx", ".rc"):
            out.add(p.parent)
    return sorted(out)


def culprits(output: str, units: list[str], lib: Path, cache: dict[str, bytes] | None = None) -> set[str]:
    """Units to leave out after a failed build, read from the compiler output (lower case names).

    * ``Unit 'X' is used by 'Y'`` and ``X not found``: Y.
    * a resource file the install lacks (``E1026 File not found: 'N'``): the unit named like the file and the
      units whose ``.dcu`` names the file.
    * ``$DENYPACKAGEUNIT 'X'`` (a unit that may not be in a package): X and every unit that uses it, found by
      the name in their ``.dcu``."""
    cache = cache if cache is not None else {}

    def data(u: str) -> bytes:
        if u not in cache:
            try:
                cache[u] = (lib / f"{u}.dcu").read_bytes().lower()
            except OSError:
                cache[u] = b""
        return cache[u]

    bad: set[str] = set()
    listed = {u.lower() for u in units}
    for m in _USED_BY.finditer(output):
        if m.group(2).lower() in listed:
            bad.add(m.group(2).lower())
    needles = {m.group(1).lower() for m in _MISSING_FILE.finditer(output)}
    stems = {n.rsplit(".", 1)[0] for n in needles}
    denied = {m.group(1).lower() for m in _DENIED.finditer(output)}
    bad |= (stems | denied) & listed
    named = needles | {x for x in stems if "." in x} | denied        # a bare stem ("behavior") is too common a word
    words = [x.encode("latin-1", "replace") for x in named]
    if words:
        for u in units:
            d = data(u)
            if any(w in d for w in words):
                bad.add(u.lower())
    if not bad:
        for m in _UNIT_ERR.finditer(output):
            if m.group(1).lower() in listed:
                bad.add(m.group(1).lower())
    return bad


def _build_part(exe: Path, lib: Path, work: Path, part: Part, psize: int, resource_dirs: list[Path],
                exclude: set[str], cache: dict[str, bytes], say: Callable[[str], None]
                ) -> tuple[Path, Path, int, set[str], int] | None:
    """Build one package in ``work``: compile, leave out the units the compiler blames, repeat. Returns
    (binary, map file, units kept, units left out, rounds), or None when every unit had to go. Raises
    MegaError."""
    shutil.rmtree(work, ignore_errors=True)
    name = f"m_{part.name}"
    write_project(work, lib, part.units, psize, resource_dirs, name, part.requires)
    excl = {u.lower() for u in exclude}
    rounds = 0
    while rounds < MAX_ROUNDS:
        rounds += 1
        keep = [u for u in part.units if u.lower() not in excl]
        if not keep:
            return None
        (work / f"{name}.dpk").write_text(dpk_text(name, keep, part.requires), encoding="latin-1")
        say(f"{part.name} round {rounds}: {len(keep)} units")
        r = subprocess.run([str(exe), f"{name}.dpk"], cwd=work, capture_output=True, text=True, errors="replace")
        if r.returncode == 0:
            break
        bad = culprits(r.stdout, keep, lib, cache) - excl
        if not bad:
            tail = " | ".join(x.strip() for x in r.stdout.splitlines()[-3:])
            raise MegaError(f"the compiler failed and no unit can be blamed: {tail}")
        say(f"  {part.name}: leaving out {len(bad)} units")
        excl |= bad
    else:
        raise MegaError("too many rounds")
    binary, mp = work / "bpl" / f"{name}.bpl", work / "bpl" / f"{name}.map"
    if not binary.is_file() or not mp.is_file():
        raise MegaError("the compiler wrote no package or no map file")
    return binary, mp, len(keep), excl, rounds


def plan(install: Path, psize: int, units: list[str], lib: Path) -> list[Part]:
    """The packages to build: one per shipped package plus one for the remaining units; a single package of all
    units when the install ships no readable packages."""
    dcps = {p.stem.lower(): p.stem for p in lib.glob("*.dcp")}
    infos = {}
    for p in shipped_packages(install, psize):
        info = read_package_info(p)
        if info:
            infos[p.name] = info
    redist = {p.name for p in (install / "Redist" / ("win64" if psize == 8 else "win32")).glob("*.bpl")}
    return plan_parts(infos, units, dcps, redist & set(infos) or None)


def build(install: Path, work: Path, psize: int, progress: Callable[[str], None] | None = None,
          exclude: set[str] | None = None, jobs: int = 4) -> MegaResult:
    """Build the packages of all compiled units for a platform in ``work`` (a folder per package), ``jobs`` at a
    time. A package that fails is listed in ``failed`` and the others are kept. Raises MegaError when the
    compiler is missing, there are no units, or no package could be built."""
    say = progress or (lambda _m: None)
    t0 = time.time()
    exe, lib = compiler_exe(install, psize), lib_dir(install, psize)
    if not exe.is_file():
        raise MegaError(f"no compiler {exe.name} in {install / 'bin'}")
    units = unit_names(lib)
    if not units:
        raise MegaError(f"no compiled units (.dcu) in {lib}")
    shutil.rmtree(work, ignore_errors=True)
    resdirs = resource_folders(install)
    parts = plan(install, psize, units, lib)
    say(f"{len(parts)} packages for {len(units)} units")
    excl0 = {u.lower() for u in (exclude or set())}
    cache: dict[str, bytes] = {}

    def run(part: Part):
        try:
            return part, _build_part(exe, lib, work / part.name, part, psize, resdirs, excl0, cache, say), None
        except MegaError as e:
            return part, None, str(e)

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        results = list(ex.map(run, sorted(parts, key=lambda p: -len(p.units))))
    pairs: list[tuple[Path, Path]] = []
    excluded: set[str] = set()
    failed: list[str] = []
    kept = rounds = 0
    for part, res, err in results:
        if res is None:
            if err:
                failed.append(f"{part.name}: {err}")
                say(f"{part.name}: failed ({err})")
            else:
                excluded |= {u.lower() for u in part.units}
            continue
        binary, mp, n, ex_units, r = res
        pairs.append((binary, mp))
        kept += n
        rounds += r
        excluded |= ex_units
    if not pairs:
        raise MegaError("no package could be built: " + "; ".join(failed))
    return MegaResult(pairs, psize, kept, sorted(excluded), rounds, time.time() - t0, failed)
