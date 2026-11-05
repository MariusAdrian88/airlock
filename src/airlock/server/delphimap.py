"""Routine names from a Delphi linker map file (DESIGN 11 "Delphi", "Signature databases from map files").

The packages of a Delphi install export their public routines only. The private ones (helpers, nested
routines, implementation-section routines, unexported generic instances) have no name in the package. A
package that is rebuilt from the compiled units of the install (``delphimega``) with the detailed map option
(``dcc32 -GD``) comes with a map file that lists every routine with its address. This module reads such a
map, pairs the addresses with the rebuilt binary and gives ``delphisigs`` the (name, code, mask) records it
needs.

Map file layout (Delphi 10 Seattle, 32- and 64-bit; one section per heading)::

    Start         Length     Name                   Class
    0001:00401000 002B4E38H .text                   CODE
    ...
    Detailed map of segments
    0001:00000000 00017E48 C=CODE     S=.text    G=(none)   M=System   ACBP=A9
    ...
      Address             Publics by Value
    0001:0000087C       System..TObject
    0001:00051EC0       System.SysUtils.TStringHelper.Split

A public is ``segment:offset name``; the offset counts from the start of the segment, whose address in the
image is the section of the same name in the PE file. Names use the Pascal form: ``Unit.Class.Method``,
nested types ``Unit.Outer.Inner.Method``, a generic instance ``Unit.{Owner}TList<System.Integer>.Add`` where
``Owner`` is the unit that declares the generic (the display name drops the brace form and the instantiating
unit). A name with an empty part (``Unit..TClass``) is the table of a type (VMT, type information), not a
routine; import thunks (``$thunk_``) are one jump each. Both are left out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from airlock.server import delphisigs as ds

_SEG = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})H?\s+(\S+)\s+(\S+)\s*$")
_PUB = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+(\S.*?)\s*$")
_MOD = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+C=(\S+)\s+S=(\S+)\s+.*\bM=(\S+)")
_GENERIC = re.compile(r"^(?P<head>.*?)\.\{(?P<owner>[^{}]+)\}(?P<rest>.+)$")
CODE_CLASSES = {"CODE", "ICODE"}


@dataclass
class MapFile:
    segments: dict[int, tuple[str, str, int]]            # segment number -> (name, class, start offset)
    publics: list[tuple[int, int, str]]                  # (segment, offset, name) in file order
    modules: list[tuple[int, int, int, str]]             # (segment, offset, length, module name)


def parse_map(text: str) -> MapFile:
    """Read the segment table, the module table and the publics. Lines that do not fit are ignored."""
    segs: dict[int, tuple[str, str, int]] = {}
    pubs: list[tuple[int, int, str]] = []
    mods: list[tuple[int, int, int, str]] = []
    state = "segs"
    for line in text.splitlines():
        if "Detailed map of segments" in line:
            state = "mods"
            continue
        if "Publics by Name" in line:
            state = "skip"
            continue
        if "Publics by Value" in line:
            state = "pubs"
            continue
        if state == "segs":
            m = _SEG.match(line)
            if m and m.group(5).isupper():
                segs[int(m.group(1), 16)] = (m.group(4), m.group(5), int(m.group(2), 16))
        elif state == "mods":
            m = _MOD.match(line)
            if m:
                mods.append((int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16), m.group(6)))
        elif state == "pubs":
            m = _PUB.match(line)
            if m:
                pubs.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    return MapFile(segs, pubs, mods)


def display_name(raw: str) -> str | None:
    """Name of a routine in the style of the export names (``Unit.Class.Method``), None for a symbol that is
    not a routine: a type table (``Unit..TClass``), an import thunk, an empty name."""
    if not raw or ".." in raw or "$thunk" in raw or raw.startswith("$"):
        return None
    name = raw.replace("&", "")
    m = _GENERIC.match(name)
    if m:                                                # ``Inst.Unit.{Owner.Unit}TList<T>.Add`` -> ``Owner.Unit.TList<T>.Add``
        name = f"{m.group('owner')}.{m.group('rest')}"
    return name or None


def section_rvas(img: ds._Pe, segs: dict[int, tuple[str, str, int]], pe_sections: list[tuple[str, int]],
                 image_base: int) -> dict[int, int]:
    """RVA of the start of each code segment of the map: the PE section of the same name, else the start
    address of the map minus the image base."""
    by_name = {n: rva for n, rva in pe_sections}
    out: dict[int, int] = {}
    for num, (name, cls, start) in segs.items():
        if cls not in CODE_CLASSES:
            continue
        if name in by_name:
            out[num] = by_name[name]
        elif start >= image_base:
            out[num] = start - image_base
    return out


def pair_psize(path: Path) -> int | None:
    """Pointer size of a PE file (4 or 8), None when it is not one."""
    try:
        with path.open("rb") as f:
            head = f.read(0x400)
        off = int.from_bytes(head[0x3C:0x40], "little")
        if head[:2] != b"MZ" or head[off:off + 4] != b"PE\0\0":
            return None
        return 8 if int.from_bytes(head[off + 24:off + 26], "little") == 0x20B else 4
    except (OSError, ValueError):
        return None


def pe_section_names(path: Path) -> list[tuple[str, int]]:
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    return [(s.Name.rstrip(b"\0").decode("latin-1"), s.VirtualAddress) for s in pe.sections]


def map_routines(path_bin: Path, path_map: Path) -> tuple[ds._Pe, dict[int, list[str]], set[int]]:
    """(image, {routine rva: [display names]}, rva of every public in a code segment) of one rebuilt binary
    and its map. The last set also holds the type tables and thunks: they end the routine before them."""
    img = ds._read_pe(path_bin)
    mp = parse_map(path_map.read_text(encoding="latin-1", errors="replace"))
    rvas = section_rvas(img, mp.segments, pe_section_names(path_bin), img.image_base)
    named: dict[int, list[str]] = {}
    starts: set[int] = set()
    for seg, off, raw in mp.publics:
        base = rvas.get(seg)
        if base is None:
            continue
        starts.add(base + off)
        nm = display_name(raw)
        if nm is None:
            continue
        lst = named.setdefault(base + off, [])
        if nm not in lst:
            lst.append(nm)
    return img, named, starts


def scan_pair(bin_str: str, map_str: str) -> tuple[int, list[tuple[str, bytes, bytes]]]:
    """(pointer size, [(name, dump, mask)]) of one binary with its map. Runs in worker processes."""
    try:
        import capstone
    except ImportError as e:                                    # pragma: no cover
        raise ds.SigError("the build needs the capstone package (pip install capstone)") from e
    img, named, starts = map_routines(Path(bin_str), Path(map_str))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if img.psize == 8 else capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = False
    return img.psize, ds.scan_named(md, img, named, starts)
