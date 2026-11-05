"""A minimal rebuild kit of a Delphi install (DESIGN 11 "Delphi", "Signature databases").

``airlock delphi-sigs build <folder> --units`` needs only a small part of an install: the command line compilers
with their helper libraries, the compiled units, the shipped packages and the few resource files that units
name. ``make_kit`` copies exactly those into a new folder, so the install itself can be removed afterwards.
``build <kit>`` works on the result like on the install. Nothing in the install is changed.

The helper libraries are found by pattern (``dcc32NNN.dll``, ``dcc64NNN.dll``, ``dcc64NNNN.dll``,
``lnkdfmNNN.dll``): the numbers change with the version. ``lnkdfm`` is needed to compile units with a form file.
The compiler configuration files name the install folder; they are rewritten to name the kit.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Callable

from airlock.server import delphimega

BIN_FILES = {"dcc32.exe", "dcc64.exe", "borlndmm.dll", "rlink32.dll", "cgrc.exe", "dcc32.cfg", "dcc64.cfg"}
BIN_PATTERNS = (re.compile(r"dcc(32|64)\d+n?\.dll$", re.I), re.compile(r"lnkdfm\d*\.dll$", re.I))
TREES = ("lib/win32/release", "lib/win64/release", "Redist/win32", "Redist/win64")
RESOURCE_EXT = {".res", ".dfm", ".fmx", ".rc"}


class KitError(RuntimeError):
    """The kit could not be made."""


def rewrite_cfg(text: str, install: Path, dest: Path) -> str:
    """Replace the install folder in a compiler configuration (either slash direction, any case)."""
    sep = "[" + "\\\\" + "/]+"
    parts = [re.escape(x) for x in re.split(sep, str(install)) if x]
    pat = re.compile(sep.join(parts), re.I)
    text = pat.sub(lambda _m: str(dest), text)
    return text


def _bin_files(folder: Path) -> list[Path]:
    try:
        return sorted(p for p in folder.iterdir() if p.is_file() and (
            p.name.lower() in BIN_FILES or any(r.match(p.name) for r in BIN_PATTERNS)))
    except OSError:
        return []


def tree_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def make_kit(install: Path, dest: Path, progress: Callable[[str], None] | None = None) -> int:
    """Copy the kit of ``install`` into ``dest``; returns its size in bytes. Raises KitError when the install has
    no compilers."""
    say = progress or (lambda _m: None)
    install, dest = install.resolve(), dest.resolve()
    if install == dest or install in dest.parents:
        raise KitError("the destination must be outside the install folder")
    if not (install / "bin" / "dcc32.exe").is_file() and not (install / "bin" / "dcc64.exe").is_file():
        raise KitError(f"no dcc32.exe / dcc64.exe in {install / 'bin'}")
    (dest / "bin").mkdir(parents=True, exist_ok=True)
    for p in _bin_files(install / "bin"):
        if p.suffix.lower() == ".cfg":
            text = p.read_text(encoding="latin-1")
            (dest / "bin" / p.name).write_text(rewrite_cfg(text, install, dest), encoding="latin-1")
        else:
            shutil.copy2(p, dest / "bin" / p.name)
    for sub in ("bin", "bin64"):
        (dest / sub).mkdir(parents=True, exist_ok=True)
        for p in (install / sub).glob("*.bpl"):
            shutil.copy2(p, dest / sub / p.name)
    for rel in TREES:
        src = install / rel
        if src.is_dir():
            say(f"copying {rel}")
            shutil.copytree(src, dest / rel, dirs_exist_ok=True)
    for folder in delphimega.resource_folders(install):
        rel = folder.relative_to(install)
        (dest / rel).mkdir(parents=True, exist_ok=True)
        for p in folder.iterdir():
            if p.is_file() and p.suffix.lower() in RESOURCE_EXT:
                shutil.copy2(p, dest / rel / p.name)
    return tree_size(dest)
