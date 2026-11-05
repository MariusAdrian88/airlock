"""Reader for Binary Ninja WARP signature files and the WARP function GUID.

Format: Vector35/warp (Apache-2.0), see DESIGN section 11 "Delphi" (WARP). A `.warp` file is a
FlatBuffers `File` whose chunks hold `SignatureChunk` tables (zlib or no compression in the
delphinja files). The reader is a minimal hand-written FlatBuffers walker: no dependency.
"""

from __future__ import annotations

import hashlib
import re
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from pathlib import Path

FUNCTION_NS = uuid.UUID("0192a179-61ac-7cef-88ed-012296e9492f")
BLOCK_NS = uuid.UUID("0192a178-7a5f-7936-8653-3cbaa7d6afe7")
CONSTRAINT_NS = uuid.UUID("019701f3-e89c-7afa-9181-371a5e98a576")
RELOC_THRESHOLD = 0x10000


class WarpError(ValueError):
    pass


def uuid5(namespace: uuid.UUID, data: bytes) -> bytes:
    """UUIDv5 as the WARP reference does it (SHA-1 of namespace bytes + data); 16 bytes."""
    h = bytearray(hashlib.sha1(namespace.bytes + data).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x50
    h[8] = (h[8] & 0x3F) | 0x80
    return bytes(h)


def block_guid(block_bytes: bytes) -> bytes:
    return uuid5(BLOCK_NS, block_bytes)


def function_guid(block_guids_by_address: list[bytes]) -> bytes:
    """Function GUID from block GUIDs already ordered by ascending start address."""
    return uuid5(FUNCTION_NS, b"".join(block_guids_by_address))


# ---- minimal FlatBuffers reader -------------------------------------------------------------


class _Tab:
    __slots__ = ("b", "pos", "vt", "vsz")

    def __init__(self, b: bytes, pos: int):
        self.b = b
        self.pos = pos
        self.vt = pos - struct.unpack_from("<i", b, pos)[0]
        self.vsz = struct.unpack_from("<H", b, self.vt)[0]

    def off(self, idx: int) -> int:
        o = 4 + 2 * idx
        if o >= self.vsz:
            return 0
        return struct.unpack_from("<H", self.b, self.vt + o)[0]

    def scalar(self, idx: int, fmt: str, default: int = 0) -> int:
        o = self.off(idx)
        return struct.unpack_from(fmt, self.b, self.pos + o)[0] if o else default

    def inline(self, idx: int, size: int) -> bytes | None:
        o = self.off(idx)
        return self.b[self.pos + o : self.pos + o + size] if o else None

    def _indirect(self, idx: int) -> int | None:
        o = self.off(idx)
        if not o:
            return None
        p = self.pos + o
        return p + struct.unpack_from("<I", self.b, p)[0]

    def table(self, idx: int) -> "_Tab | None":
        p = self._indirect(idx)
        return None if p is None else _Tab(self.b, p)

    def string(self, idx: int) -> str | None:
        p = self._indirect(idx)
        if p is None:
            return None
        n = struct.unpack_from("<I", self.b, p)[0]
        return self.b[p + 4 : p + 4 + n].decode("utf-8", "replace")

    def bytes_vec(self, idx: int) -> bytes:
        p = self._indirect(idx)
        if p is None:
            return b""
        n = struct.unpack_from("<I", self.b, p)[0]
        return self.b[p + 4 : p + 4 + n]

    def tables(self, idx: int) -> list["_Tab"]:
        p = self._indirect(idx)
        if p is None:
            return []
        n = struct.unpack_from("<I", self.b, p)[0]
        out = []
        for i in range(n):
            q = p + 4 + 4 * i
            out.append(_Tab(self.b, q + struct.unpack_from("<I", self.b, q)[0]))
        return out


@dataclass(slots=True)
class WarpFunction:
    guid: bytes
    name: str
    constraints: tuple[tuple[bytes, int], ...] = ()


@dataclass(slots=True)
class WarpLib:
    functions: dict[bytes, list[WarpFunction]] = field(default_factory=dict)

    def __len__(self) -> int:
        return sum(len(v) for v in self.functions.values())


def _read_signature_chunk(data: bytes, lib: WarpLib, with_constraints: bool) -> None:
    root = _Tab(data, struct.unpack_from("<I", data, 0)[0])
    for f in root.tables(0):
        guid = f.inline(0, 16)
        sym = f.table(1)
        name = sym.string(0) if sym else None
        if guid is None or not name:
            continue
        cons: tuple[tuple[bytes, int], ...] = ()
        if with_constraints:
            cons = tuple(
                (c.inline(0, 16) or b"", c.scalar(1, "<q")) for c in f.tables(3)
            )
        lib.functions.setdefault(guid, []).append(WarpFunction(guid, name, cons))


def read_warp(data: bytes, *, with_constraints: bool = False) -> WarpLib:
    """Parse a `.warp` file; only Signatures chunks (type 0) are read."""
    if len(data) < 8:
        raise WarpError("file too short")
    try:
        root = _Tab(data, struct.unpack_from("<I", data, 0)[0])
        lib = WarpLib()
        for ch in root.tables(1):
            hdr = ch.table(0)
            if hdr is None:
                continue
            ctype = hdr.scalar(1, "<B")
            comp = hdr.scalar(2, "<B")
            raw = ch.bytes_vec(1)
            if ctype != 0:
                continue
            if raw[:4] == b"\x28\xb5\x2f\xfd":
                raw = _zstd(raw)
            elif comp != 0 or raw[:1] == b"\x78":
                raw = zlib.decompress(raw)  # delphinja files: header says 1, data is zlib
            _read_signature_chunk(raw, lib, with_constraints)
        return lib
    except (struct.error, IndexError, zlib.error) as e:
        raise WarpError(f"bad warp file: {e}") from e


def _zstd(raw: bytes) -> bytes:
    try:
        from compression import zstd  # type: ignore[import-not-found]  # Python 3.14

        return zstd.decompress(raw)
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore[import-not-found]

        return zstandard.ZstdDecompressor().decompressobj().decompress(raw)
    except ImportError as e:
        raise WarpError("zstd chunk: install 'zstandard'") from e


def read_warp_file(path: Path, *, with_constraints: bool = False) -> WarpLib:
    return read_warp(Path(path).read_bytes(), with_constraints=with_constraints)


# ---- GUID from the worker's blocks (worker/ghidra_ops/warp.py) -------------------------------

F_CONST, F_CALL, F_JMP, F_JCC, F_RET, F_NOP, F_OUT = 1, 2, 4, 8, 16, 32, 64


def _variant(flags: int) -> bool:
    """Whole instruction is zeroed. Calibrated against Binary Ninja libraries (DESIGN section 11)."""
    if not flags & F_CONST or flags & (F_JCC | F_RET):
        return False
    return not flags & F_JMP or bool(flags & F_OUT)


def block_bytes(raw: bytes, meta: list[int]) -> bytes:
    """Masked bytes of one block. `meta` is [len, flags, len, flags, ...] per instruction."""
    out = bytearray()
    pos = 0
    for i in range(0, len(meta) - 1, 2):
        n, fl = meta[i], meta[i + 1]
        if not fl & F_NOP:
            out += bytes(n) if _variant(fl) else raw[pos : pos + n]
        pos += n
    return bytes(out)


def guid_from_blocks(blocks: list[list]) -> bytes | None:
    """Function GUID from worker blocks `[start, hexbytes, meta]`; None for an empty function."""
    if not blocks:
        return None
    guids = [block_guid(block_bytes(bytes.fromhex(b[1]), b[2])) for b in sorted(blocks, key=lambda b: b[0])]
    return function_guid(guids)


# ---- blocks from the PE bytes (capstone, 32-bit x86) ------------------------------------------


def in_regions(regions: list[tuple[int, int]], v: int) -> bool:
    """WARP's `is_address_relocatable`: inside a region or within 0x10000 of one."""
    for lo, hi in regions:
        if lo <= v < hi:
            return True
        if v > hi and v > RELOC_THRESHOLD and v <= hi + RELOC_THRESHOLD:
            return True
        if v < lo and v > RELOC_THRESHOLD and v >= lo - RELOC_THRESHOLD:
            return True
    return False


def _capstone(psize: int = 4):  # pragma: no cover - import guard
    try:
        import capstone
        from capstone import x86
    except ImportError as e:
        raise WarpError("capstone is needed for WARP matching (pip install airlock[sigs])") from e
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if psize == 8 else capstone.CS_MODE_32)
    cs.detail = True
    return capstone, x86, cs


def _insn_flags(i, x86, regions: list[tuple[int, int]], lo: int, hi: int, wide: bool = False) -> int:
    f = 0
    g = i.groups
    ops = i.operands
    if i.id in (x86.X86_INS_RET, x86.X86_INS_RETF, x86.X86_INS_IRET):
        f |= F_RET
    elif x86.X86_GRP_CALL in g:
        f |= F_CALL
    elif x86.X86_GRP_JUMP in g:
        if i.mnemonic == "jmp":
            f |= F_JMP
            if not ops or ops[0].type != x86.X86_OP_IMM or not lo <= ops[0].imm < hi:
                f |= F_OUT
        else:
            f |= F_JCC
    mn = i.mnemonic
    if mn == "nop":
        f |= F_NOP
    elif mn in ("mov", "xchg") and len(ops) == 2 and ops[0].type == ops[1].type == x86.X86_OP_REG \
            and ops[0].reg == ops[1].reg:
        f |= F_NOP
    elif mn == "lea" and len(ops) == 2 and ops[1].type == x86.X86_OP_MEM:
        m = ops[1].mem
        if m.base == ops[0].reg and m.index == 0 and m.disp == 0:
            f |= F_NOP
    mask = 0xFFFFFFFFFFFFFFFF if wide else 0xFFFFFFFF
    for o in ops:
        if o.type == x86.X86_OP_IMM and in_regions(regions, o.imm & mask):
            f |= F_CONST
        elif o.type == x86.X86_OP_MEM:
            m = o.mem
            if m.base == x86.X86_REG_RIP:                      # x64: displacement relative to the next instruction
                if in_regions(regions, (i.address + i.size + m.disp) & mask):
                    f |= F_CONST
            elif (m.disp or m.base == 0) and in_regions(regions, m.disp & mask):
                f |= F_CONST
    return f


def image_blocks(img, entry: int, size: int, regions: list[tuple[int, int]], tools=None) -> list[list]:
    """Basic blocks `[start, hexbytes, meta]` of the function `[entry, entry+size)` by recursive descent.

    A block ends at a jump or return, or before a branch target; calls do not end blocks."""
    _, x86, cs = tools or _capstone(getattr(img, "psize", 4))
    wide = getattr(img, "psize", 4) == 8
    end = entry + size
    insn: dict[int, object] = {}
    leaders = {entry}
    work = [entry]
    while work:
        a = work.pop()
        while entry <= a < end and a not in insn:
            code = img.read(a, 15) or img.read(a, max(1, min(15, end - a)))
            if not code:
                break
            ii = next(cs.disasm(code, a, 1), None)
            if ii is None:
                break
            insn[a] = ii
            nxt = a + ii.size
            if ii.id in (x86.X86_INS_RET, x86.X86_INS_RETF, x86.X86_INS_IRET):
                break
            if x86.X86_GRP_JUMP in ii.groups:
                o = ii.operands[0] if ii.operands else None
                if o is not None and o.type == x86.X86_OP_IMM and entry <= o.imm < end:
                    work.append(o.imm)
                    leaders.add(o.imm)
                if ii.mnemonic == "jmp":
                    break
                leaders.add(nxt)
            a = nxt
    out = []
    for lead in sorted(leaders & insn.keys()):
        raw = bytearray()
        meta: list[int] = []
        a = lead
        while a in insn and (a == lead or a not in leaders):
            ii = insn[a]
            fl = _insn_flags(ii, x86, regions, entry, end, wide)
            raw += bytes(ii.bytes)
            meta += [ii.size, fl]
            a += ii.size
            if fl & (F_RET | F_JMP | F_JCC):
                break
        out.append([lead, bytes(raw).hex(), meta])
    return out


def image_regions(img) -> list[tuple[int, int]]:
    return [(s.va, s.end) for s in img.sections]


# delphinja library per compiler version (stem of ``delphi-rtl-<stem>.warp``), best first
_YEAR_COMPILER = {"2": 9, "3": 10, "4": 12, "5": 13, "6": 14, "7": 15, "2005": 17, "2006": 18, "2007": 19,
                  "2009": 20, "2010": 21, "2011": 22, "2012": 23, "2013": 24, "2014": 25}


def library_stems(comp: int | None) -> list[str]:
    """Stems of the delphinja libraries that can name a binary of compiler version `comp`
    (34 = 10.4, 35 = 11); empty when the compiler is unknown."""
    if comp is None:
        return []
    if comp >= 30:      # compilers 30 to 36+ measured: all three name routines (99% right on 10.4-only and xe2plus-only)
        return ["10.4-only", "core-11", "xe2plus-only"]
    if comp >= 26:
        return ["core-11", "xe2plus-only"]
    out = [y + "-only" for y, c in _YEAR_COMPILER.items() if c == comp]
    return out + ["core-8"] + (["xe2plus-only"] if comp >= 22 else [])


OWN_PREFIX = "airlock-rtl-"          # libraries made by `delphi-sigs warp-build`: ``airlock-rtl-win64.warp``


def warp_stem(path: Path) -> str | None:
    """Stem of a library file: ``core-11`` for delphinja's ``delphi-rtl-core-11.warp``, ``win64`` for an own
    ``airlock-rtl-win64.warp``."""
    n = path.name
    if n.endswith(".warp"):
        for pre in ("delphi-rtl-", OWN_PREFIX):
            if n.startswith(pre):
                return n[len(pre):-len(".warp")]
    return None


def own_stem(stem: str, psize: int) -> bool:
    """True for the stem of an own library of the pointer size (any compiler version)."""
    return stem == ("win64" if psize == 8 else "win32")


_CACHE: dict[tuple[str, int, int], WarpLib] = {}


def load_lib(path: Path) -> WarpLib:
    """`read_warp_file` with a small per-process cache."""
    st = path.stat()
    key = (str(path), st.st_size, st.st_mtime_ns)
    lib = _CACHE.get(key)
    if lib is None:
        lib = read_warp_file(path)
        while len(_CACHE) >= 3:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = lib
    return lib


# units that the libraries of old compilers name without the namespace of later releases
_SYSTEM_UNITS = {"SysUtils", "Classes", "Types", "Variants", "Math", "StrUtils", "DateUtils", "TypInfo", "Contnrs",
                 "IniFiles", "Rtti", "ZLib", "Character", "SyncObjs", "Masks", "UITypes", "Generics.Collections",
                 "Generics.Defaults", "AnsiStrings", "Hash", "IOUtils", "Zip", "JSON", "Threading", "WideStrUtils",
                 "VarUtils", "Actions", "Win.Registry", "Win.ComObj", "StdConvs", "ConvUtils", "MaskUtils"}
_VCL_UNITS = {"Graphics", "Controls", "Forms", "StdCtrls", "ExtCtrls", "ComCtrls", "Dialogs", "Menus", "Grids",
              "Buttons", "ActnList", "ActnMan", "Themes", "Clipbrd", "CheckLst", "Consts", "ImgList", "Mask",
              "Tabs", "Printers", "ToolWin", "ExtDlgs", "ValEdit", "Imaging.jpeg"}
_WINAPI_UNITS = {"Windows", "Messages", "ShlObj", "ActiveX", "CommCtrl", "ShellAPI", "RichEdit", "MultiMon",
                 "UxTheme", "ComObj"}


_GENERIC_PART = re.compile(r"^([A-Za-z]\w*?)__([1-9])$")


def generic_part(part: str) -> str:
    """``TDictionary__2`` -> ``TDictionary<T>``: the arity suffix of a generic instance in delphinja names, in
    the form of the other tiers (the type arguments are program types, see ``delphirtti.normalize_class``)."""
    m = _GENERIC_PART.match(part)
    return f"{m.group(1)}<T>" if m else part


def collapse_generics(name: str) -> str:
    """``A.TDictionary<System.string,TList<X>>.Add`` -> ``A.TDictionary<T>.Add`` (balanced brackets)."""
    out: list[str] = []
    depth = 0
    for ch in name:
        if ch == "<":
            if depth == 0:
                out.append("<T>")
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def instance_args(class_names: list[tuple[str, str]]) -> dict[str, set[str]]:
    """{``Unit.Base``: {type argument text}} from (unit, class name) rows such as
    (``System.Generics.Collections``, ``TDictionary<System.string,System.Integer>``)."""
    out: dict[str, set[str]] = {}
    for unit, cls in class_names:
        m = re.match(r"^(\w+)<(.+)>$", cls)
        if m and "<" not in m.group(1):
            out.setdefault(f"{unit}.{m.group(1)}" if unit else m.group(1), set()).add(m.group(2))
    return out


def refine_generics(names: list[str], instances: dict[str, set[str]]) -> list[str]:
    """Put the real type arguments into ``Unit.TBase<T>`` when the program has exactly one instance of that
    generic class (several instances share the code, so then the placeholder stays)."""
    out = []
    for n in names:
        def sub(m: re.Match) -> str:
            args = instances.get(m.group(1))
            return f"{m.group(1)}<{next(iter(args))}>" if args and len(args) == 1 else m.group(0)
        out.append(re.sub(r"([\w.]+)<T>", sub, n, count=1))
    return out


def dotted(name: str) -> str:
    """WARP `Unit::Class::Member` as the other tiers write it (`Unit.Class.Member`). A leading unit that
    only old compilers wrote without its namespace (`SysUtils`, `Graphics`, `Windows`) gets it back."""
    parts = name.split("::")
    parts[1:] = [generic_part(p) for p in parts[1:]]
    unit = parts[0]
    for ns, units in (("System", _SYSTEM_UNITS), ("Vcl", _VCL_UNITS), ("Winapi", _WINAPI_UNITS)):
        if unit in units:
            parts[0] = f"{ns}.{unit}"
            break
    else:
        if unit == "DB":
            parts[0] = "Data.DB"
    out = ".".join(parts)
    return out + "." if parts[-1] == "_DF_" else out      # the IDR spelling of the unit finalizer


def match_functions(libs: "WarpLib | list[WarpLib]", img, funcs: list[tuple[int, int | None]], *,
                    min_size: int = 16, max_names: int = 3) -> dict[int, list[str]]:
    """{entry: names} for functions whose WARP GUID is in a library. Ambiguous GUIDs (more than `max_names`
    different names) and small functions are skipped."""
    libs = [libs] if isinstance(libs, WarpLib) else libs
    if not any(l.functions for l in libs):
        return {}
    tools = _capstone(img.psize)
    regions = image_regions(img)
    out: dict[int, list[str]] = {}
    for entry, size in funcs:
        if not size or size < min_size:
            continue
        g = guid_from_blocks(image_blocks(img, entry, size, regions, tools))
        if not g:
            continue
        names = sorted({dotted(w.name) for l in libs for w in l.functions.get(g, ())})
        if names and len(names) <= max_names:
            out[entry] = names
    return out


# ---- own libraries (`delphi-sigs warp-build`) ---------------------------------------------------
#
# delphinja ships no 64-bit library and none for the newest compilers. An own library holds the WARP function
# GUID (same block rules as above, x64 operands included) of every routine that the map files of the Delphi
# packages name. It is written in the layout the reader above understands (a FlatBuffers `File` with one
# zlib compressed Signatures chunk), so `read_warp` loads it; names are already in the dotted form of the other
# tiers. Whether Binary Ninja itself loads it is not checked.

LIB_MIN_SIZE = 16          # smaller routines are not matched either
LIB_MAX_NAMES = 3          # a GUID with more names is ambiguous: `match_functions` skips it, so it is not stored


class _FbWriter:
    """Tiny FlatBuffers writer: tables parent first, offsets patched at the end."""

    def __init__(self) -> None:
        self.buf = bytearray(4)
        self.patches: list[tuple[int, int]] = []

    def table(self, fields: list[tuple[int, str, object]]) -> int:
        sizes = {"u8": 1, "u16": 2, "u32": 4, "i64": 8}
        n = max(i for i, _, _ in fields) + 1
        vt = len(self.buf)
        self.buf += bytes(4 + 2 * n)
        pos = len(self.buf)
        struct.pack_into("<HH", self.buf, vt, 4 + 2 * n, 0)
        self.buf += struct.pack("<i", pos - vt)
        off = 4
        for idx, kind, val in fields:
            struct.pack_into("<H", self.buf, vt + 4 + 2 * idx, off)
            if kind == "ref":
                self.buf += bytes(4)
                off += 4
            elif kind == "raw":
                self.buf += val  # type: ignore[operator]
                off += len(val)  # type: ignore[arg-type]
            else:
                self.buf += struct.pack({"u8": "<B", "u16": "<H", "u32": "<I", "i64": "<q"}[kind], val)
                off += sizes[kind]
        struct.pack_into("<H", self.buf, vt + 2, off)
        return pos

    def patch(self, at: int, target: int) -> None:
        self.patches.append((at, target))

    def string(self, s: str) -> int:
        pos = len(self.buf)
        raw = s.encode()
        self.buf += struct.pack("<I", len(raw)) + raw + b"\0"
        return pos

    def vector(self, count: int) -> int:
        """A vector of `count` offsets (to be patched); returns its position."""
        pos = len(self.buf)
        self.buf += struct.pack("<I", count) + bytes(4 * count)
        return pos

    def finish(self, root: int) -> bytes:
        for at, target in self.patches:
            struct.pack_into("<I", self.buf, at, target - at)
        struct.pack_into("<I", self.buf, 0, root)
        return bytes(self.buf)


def write_warp(funcs: list[tuple[bytes, str]]) -> bytes:
    """A `.warp` file with one zlib compressed signature chunk holding `funcs` (guid, name)."""
    sc = _FbWriter()
    root = sc.table([(0, "ref", 0)])
    vec = sc.vector(len(funcs))
    sc.patch(root + 4, vec)
    for i, (guid, name) in enumerate(funcs):
        f = sc.table([(0, "raw", guid), (1, "ref", 0)])
        sc.patch(vec + 4 + 4 * i, f)
        sym = sc.table([(0, "ref", 0)])
        sc.patch(sym + 4, sc.string(name))
        sc.patch(f + 4 + 16, sym)
    chunk = zlib.compress(sc.finish(root), 6)
    fb = _FbWriter()
    file_root = fb.table([(0, "ref", 0), (1, "ref", 0)])
    hdr = fb.table([(0, "u16", 1)])
    fb.patch(file_root + 4, hdr)
    chunks = fb.vector(1)
    fb.patch(file_root + 8, chunks)
    ch = fb.table([(0, "ref", 0), (1, "ref", 0)])
    fb.patch(chunks + 4, ch)
    fb.patch(ch + 4, fb.table([(0, "u16", 1), (1, "u8", 0), (2, "u8", 1), (3, "u32", len(chunk))]))
    data = len(fb.buf)
    fb.buf += struct.pack("<I", len(chunk)) + chunk
    fb.patch(ch + 8, data)
    return fb.finish(file_root)


def library_pair(bin_str: str, map_str: str) -> list[tuple[bytes, str]]:
    """(GUID, dotted name) of every routine a map file names in one rebuilt package. Runs in worker processes."""
    from airlock.server import delphimap
    from airlock.server.cpp import Image
    bin_path = Path(bin_str)
    _pe, named, starts = delphimap.map_routines(bin_path, Path(map_str))
    img = Image.from_pe(bin_path)
    if img is None:
        return []
    tools = _capstone(img.psize)
    regions = image_regions(img)
    srt = sorted(starts)
    ends = {s.va: s.end for s in img.sections}
    out: list[tuple[bytes, str]] = []
    import bisect
    for rva in sorted(named):
        va = img.base + rva
        j = bisect.bisect_right(srt, rva)
        size = (srt[j] - rva) if j < len(srt) else 16
        sec_end = next((e for lo, e in ends.items() if lo <= va < e), va + size)
        size = min(size, sec_end - va)
        if size < LIB_MIN_SIZE:
            continue
        g = guid_from_blocks(image_blocks(img, va, size, regions, tools))
        if g:
            out += [(g, collapse_generics(n)) for n in named[rva]]
    return out


def collect_library(pairs: list[tuple[Path, Path]], jobs: int = 4, progress=None) -> dict[bytes, set[str]]:
    """{GUID: names} of the (binary, map) pairs, one worker process per pair."""
    from concurrent.futures import ProcessPoolExecutor
    by_guid: dict[bytes, set[str]] = {}
    with ProcessPoolExecutor(max_workers=max(1, jobs)) as ex:
        futs = [(b, ex.submit(library_pair, str(b), str(m))) for b, m in pairs]
        for b, fut in futs:
            got = fut.result()
            for g, n in got:
                by_guid.setdefault(g, set()).add(n)
            if progress:
                progress(f"{b.name}: {len(got)} routines")
    return by_guid


def write_library(by_guid: dict[bytes, set[str]], dest: Path) -> tuple[int, int]:
    """Write `{GUID: names}` to `dest`; ambiguous GUIDs are left out. Returns (GUIDs, names) written."""
    funcs = [(g, n) for g in sorted(by_guid) if len(by_guid[g]) <= LIB_MAX_NAMES for n in sorted(by_guid[g])]
    if not funcs:
        raise WarpError("no routine could be read from the packages")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(write_warp(funcs))
    return len({g for g, _ in funcs}), len(funcs)


def build_library(pairs: list[tuple[Path, Path]], dest: Path, jobs: int = 4,
                  progress=None) -> tuple[int, int]:
    """Write the library of the (binary, map) pairs to `dest`. Returns (GUIDs, names) written."""
    return write_library(collect_library(pairs, jobs, progress), dest)
