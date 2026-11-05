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

Some units cannot be part of the package (a missing resource file that the install does not ship, a unit of a
product that is not installed). The compiler names the problem; the unit is left out and the build repeats. The
leftovers are listed in the result.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
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
    binary: Path
    map: Path
    psize: int
    units: int
    excluded: list[str] = field(default_factory=list)
    rounds: int = 0
    seconds: float = 0.0


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


def write_project(work: Path, lib: Path, units: list[str], psize: int, resource_dirs: list[Path]) -> None:
    """``mega.dpk`` (the contains clause) and ``mega.cfg`` (compiler switches, read next to the project)."""
    (work / "dcu").mkdir(parents=True, exist_ok=True)
    (work / "bpl").mkdir(parents=True, exist_ok=True)
    (work / "dcp").mkdir(parents=True, exist_ok=True)
    (work / "mega.dpk").write_text("package mega;\n{$RUNONLY}\n{$IMPLICITBUILD OFF}\ncontains\n  "
                                   + ",\n  ".join(units) + ";\nend.\n", encoding="latin-1")
    ns = NAMESPACES + (";Bde" if psize == 4 else "")
    cfg = ["-B", "-GD", "-Q", "-W-", "-H-", f"-NS{ns}", f"-LE{work / 'bpl'}", f"-LN{work / 'dcp'}",
           f"-N0{work / 'dcu'}", f"-NU{work / 'dcu'}", f"-E{work / 'bpl'}",
           f'-U"{lib}"', f'-I"{lib}"', f'-R"{lib}"']
    cfg += [f'-R"{d}"' for d in resource_dirs]
    (work / "mega.cfg").write_text("\n".join(cfg) + "\n", encoding="latin-1")


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


def build(install: Path, work: Path, psize: int, progress: Callable[[str], None] | None = None,
          exclude: set[str] | None = None) -> MegaResult:
    """Build the package of all compiled units for a platform in ``work``. Raises MegaError."""
    say = progress or (lambda _m: None)
    t0 = time.time()
    exe, lib = compiler_exe(install, psize), lib_dir(install, psize)
    if not exe.is_file():
        raise MegaError(f"no compiler {exe.name} in {install / 'bin'}")
    units = unit_names(lib)
    if not units:
        raise MegaError(f"no compiled units (.dcu) in {lib}")
    shutil.rmtree(work, ignore_errors=True)
    write_project(work, lib, units, psize, resource_folders(install))
    excl = {u.lower() for u in (exclude or set())}
    rounds = 0
    cache: dict[str, bytes] = {}
    while rounds < MAX_ROUNDS:
        rounds += 1
        keep = [u for u in units if u.lower() not in excl]
        (work / "mega.dpk").write_text("package mega;\n{$RUNONLY}\n{$IMPLICITBUILD OFF}\ncontains\n  "
                                       + ",\n  ".join(keep) + ";\nend.\n", encoding="latin-1")
        say(f"round {rounds}: {len(keep)} units")
        r = subprocess.run([str(exe), "mega.dpk"], cwd=work, capture_output=True, text=True, errors="replace")
        if r.returncode == 0:
            break
        bad = culprits(r.stdout, keep, lib, cache) - excl
        if not bad:
            tail = "\n".join(r.stdout.splitlines()[-4:])
            raise MegaError(f"the compiler failed and no unit can be blamed:\n{tail}")
        say(f"  leaving out {len(bad)} units")
        excl |= bad
    else:
        raise MegaError("too many rounds")
    binary, mp = work / "bpl" / "mega.bpl", work / "bpl" / "mega.map"
    if not binary.is_file() or not mp.is_file():
        raise MegaError("the compiler wrote no package or no map file")
    return MegaResult(binary, mp, psize, len(keep), sorted(excl), rounds, time.time() - t0)
