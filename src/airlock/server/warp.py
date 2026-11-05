"""Reader for Binary Ninja WARP signature files and the WARP function GUID.

Format: Vector35/warp (Apache-2.0), see DESIGN section 11 "Delphi" (WARP). A `.warp` file is a
FlatBuffers `File` whose chunks hold `SignatureChunk` tables (zlib or no compression in the
delphinja files). The reader is a minimal hand-written FlatBuffers walker: no dependency.
"""

from __future__ import annotations

import hashlib
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


def _capstone():  # pragma: no cover - import guard
    try:
        import capstone
        from capstone import x86
    except ImportError as e:
        raise WarpError("capstone is needed for WARP matching (pip install airlock[sigs])") from e
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    return capstone, x86, cs


def _insn_flags(i, x86, regions: list[tuple[int, int]], lo: int, hi: int) -> int:
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
    for o in ops:
        if o.type == x86.X86_OP_IMM and in_regions(regions, o.imm & 0xFFFFFFFF):
            f |= F_CONST
        elif o.type == x86.X86_OP_MEM and (o.mem.disp or o.mem.base == 0) and \
                in_regions(regions, o.mem.disp & 0xFFFFFFFF):
            f |= F_CONST
    return f


def image_blocks(img, entry: int, size: int, regions: list[tuple[int, int]], tools=None) -> list[list]:
    """Basic blocks `[start, hexbytes, meta]` of the function `[entry, entry+size)` by recursive descent.

    A block ends at a jump or return, or before a branch target; calls do not end blocks."""
    _, x86, cs = tools or _capstone()
    end = entry + size
    insn: dict[int, object] = {}
    leaders = {entry}
    work = [entry]
    while work:
        a = work.pop()
        while entry <= a < end and a not in insn:
            code = img.read(a, 15)
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
            fl = _insn_flags(ii, x86, regions, entry, end)
            raw += bytes(ii.bytes)
            meta += [ii.size, fl]
            a += ii.size
            if fl & (F_RET | F_JMP | F_JCC):
                break
        out.append([lead, bytes(raw).hex(), meta])
    return out


def image_regions(img) -> list[tuple[int, int]]:
    return [(s.va, s.end) for s in img.sections]


def match_functions(lib: WarpLib, img, funcs: list[tuple[int, int | None]], *, min_size: int = 16,
                    max_names: int = 3) -> dict[int, list[str]]:
    """{entry: names} for functions whose WARP GUID is in `lib`. Ambiguous GUIDs (more than `max_names`
    different names) and small functions are skipped. 32-bit images only."""
    if img.psize != 4 or not lib.functions:
        return {}
    tools = _capstone()
    regions = image_regions(img)
    out: dict[int, list[str]] = {}
    for entry, size in funcs:
        if not size or size < min_size:
            continue
        g = guid_from_blocks(image_blocks(img, entry, size, regions, tools))
        hit = lib.functions.get(g) if g else None
        if hit:
            names = sorted({w.name for w in hit})
            if len(names) <= max_names:
                out[entry] = names
    return out
