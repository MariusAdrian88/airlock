"""Exact-version Delphi RTL / VCL signatures built from the runtime packages of a local Delphi install
(DESIGN 11 "Delphi", "Signature databases").

A Delphi install ships the RTL and VCL as packages (``rtl230.bpl``, ``vcl230.bpl``, ...). A 32-bit package
exports every interface routine under its C++ Builder style mangled name (``@System@Classes@TList@Add$qqrpv``),
a 64-bit package under an Itanium ABI name (``_ZN6System7Classes5TList3AddEPv``, see ``itanium``).
For each exported routine this module takes the code bytes and masks what depends on the position:

* relocation table entries (32-bit absolute addresses, 64-bit ``DIR64``),
* ``rel32`` operands of ``call`` / ``jmp`` / ``jcc`` whose target is outside the routine,
* RIP-relative displacements in 64-bit code whose target is outside the routine.

Code that is linked statically into a program is the same machine code with the same operands changed, so
the masked bytes match it (``idr.match_all`` does the matching; a database loads into an ``idr.Kb``).
Routine bounds: in 64-bit packages the ``.pdata`` table (exact start and size; chained pieces are joined). In
32-bit packages the next export, or earlier at the end found by a linear sweep (a ``ret`` or an
unconditional jump once no forward branch reaches past it). A routine that cannot be swept to its end (a
jump table in the code stream that is not relocated, undecodable bytes) keeps the swept prefix; a prefix
still matches the start of the statically linked routine.

The decoder is capstone (BSD-3-Clause), needed by the build command only; matching needs no decoder. The
database is derived data of a licensed install and is never committed.
"""

from __future__ import annotations

import bisect
import json
import logging
import re
import struct
import time
import zlib
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from airlock.server import idr, itanium

log = logging.getLogger("airlock")

MAGIC = b"AIRLOCK-DELPHISIG\x01"            # 18 bytes
SIG_NAME = re.compile(r"^(\d+)-(32|64)\.sigdb$")
MAX_LEN = 2048                               # bytes kept of one routine (a prefix of a longer one)
MAX_SWEEP = 16384                            # bytes swept looking for the end of one routine
MIN_LEN = 6
_CORE = re.compile(r"(rtl|vcl|vclx|dbrtl)\d+\.bpl$", re.I)
_COMPILER = re.compile(rb"(?:Embarcadero|CodeGear) Delphi for Win(?:32|64) compiler version (\d+)\.(\d+)")


class SigError(ValueError):
    """A signature database that cannot be built or read."""


# -- demangling -------------------------------------------------------------------------------

_SPECIAL = {"ctr": "Create", "dtr": "Destroy", "cctr": "ClassCreate", "cdtr": "ClassDestroy"}


def _split_top(s: str) -> list[str]:
    """Split on ``@`` outside ``%...%`` template groups. A ``%`` opens a group when it follows ``@`` (or
    starts the string) and closes one otherwise."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    prev = "@"
    for ch in s:
        if ch == "%":
            depth += 1 if prev == "@" else -1
            depth = max(depth, 0)
        if ch == "@" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        prev = ch
    parts.append("".join(cur))
    return parts


def _find_sig(s: str) -> int:
    """Index of the first ``$q`` (start of the parameter list) outside template groups, or -1."""
    depth = 0
    prev = "@"
    for i, ch in enumerate(s):
        if ch == "%":
            depth += 1 if prev == "@" else -1
            depth = max(depth, 0)
        elif ch == "$" and depth == 0 and s[i + 1:i + 2] == "q":
            return i
        prev = ch
    return -1


def _generic(group: str) -> str:
    """``%TList__1$p25System@Classes@TComponent%`` -> ``TList<T>``. The type arguments are left out: the
    code of most instantiations is the same, so a name with one argument would mislead."""
    inner = group[1:-1] if group.endswith("%") else group[1:]
    return re.sub(r"__\d+$", "", inner.partition("$")[0]) + "<T>"


def demangle(name: str) -> str | None:
    """``@System@@LStrAsg$qqrr...`` -> ``System.@LStrAsg``; ``@System@Classes@TList@Add$qqrpv`` ->
    ``System.Classes.TList.Add``. None for exports that are not routines (no parameter list: type info,
    class tables, resource strings)."""
    if not name.startswith("@"):
        return None
    cut = _find_sig(name)
    if cut <= 1:
        return None
    parts = _split_top(name[1:cut])
    out: list[str] = []
    pending = ""
    for p in parts:
        if not p:
            pending = "@"
            continue
        if p.startswith("$b"):
            p = _SPECIAL.get(p[2:], "op_" + p[2:])
        elif p.startswith("%"):
            p = _generic(p)
        out.append(pending + p)
        pending = ""
    if not out or pending:
        return None
    return ".".join(out)


# -- package scanning -------------------------------------------------------------------------

@dataclass
class _Pe:
    data: bytes
    psize: int
    image_base: int
    sections: list[tuple[int, int, int, int, bool]]    # rva, vsize, raw offset, raw size, executable
    relocs: dict[int, int]                              # rva -> bytes covered (4 or 8)
    exports: list[tuple[int, str]]                      # (rva, mangled name)
    reloc_rvas: list[int] | None = None                 # sorted keys of ``relocs``
    funcs: dict[int, int] | None = None                 # 64-bit: .pdata routine start rva -> end rva


def _read_pe(path: Path) -> _Pe:
    import pefile
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
    psize = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData,
             bool(s.Characteristics & 0x20000000)) for s in pe.sections]
    relocs: dict[int, int] = {}
    for blk in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for e in blk.entries:
            if e.type == 3:
                relocs[e.rva] = 4
            elif e.type == 10:
                relocs[e.rva] = 8
    img = _Pe(data, psize, pe.OPTIONAL_HEADER.ImageBase, secs, relocs, [])
    img.exports = _exports(pe, img)
    if psize == 8:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]                 # IMAGE_DIRECTORY_ENTRY_EXCEPTION
        img.funcs = read_pdata(img, d.VirtualAddress, d.Size)
    return img


def read_pdata(img: _Pe, rva: int, size: int) -> dict[int, int]:
    """Routines of a 64-bit image from the exception directory (``RUNTIME_FUNCTION``: begin, end, unwind
    info). Returns {start rva: end rva}. An entry whose unwind info is chained to a parent is a piece of the
    parent: a piece that starts where the routine ends extends it, any other piece (cold code elsewhere) is
    ignored. The table is not necessarily sorted."""
    o = _rva_off(img, rva) if rva and size else None
    if o is None:
        return {}
    n = min(size, len(img.data) - o) // 12
    ents = sorted(struct.unpack_from("<III", img.data, o + 12 * i) for i in range(n))
    parent: dict[int, int] = {}                  # begin of a chained piece -> begin of its parent
    for b, _e, u in ents:
        uo = _rva_off(img, u & ~1)
        if uo is None or uo + 4 > len(img.data) or not (img.data[uo] >> 3) & 4:
            continue
        po = uo + 4 + ((img.data[uo + 2] + 1) & ~1) * 2
        if po + 4 <= len(img.data):
            parent[b] = struct.unpack_from("<I", img.data, po)[0]
    ends = {b: e for b, e, _u in ents}
    funcs = {b: e for b, e, _u in ents if b not in parent and e > b}
    for b, _e, _u in ents:                       # sorted: a piece follows the entry it extends
        if b not in parent:
            continue
        root, hops = parent[b], 0
        while root in parent and hops < 8:
            root, hops = parent[root], hops + 1
        if root in funcs and funcs[root] == b:
            funcs[root] = max(funcs[root], ends[b])
    return funcs


def _rva_off(img: _Pe, rva: int) -> int | None:
    for va, vs, raw, rs, _x in img.sections:
        if va <= rva < va + max(vs, rs) and rva - va < rs:
            return raw + rva - va
    return None


def _exports(pe, img: _Pe) -> list[tuple[int, str]]:
    """Name table of the export directory, read directly (pefile stops at 8192 symbols)."""
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    o = _rva_off(img, d.VirtualAddress) if d.VirtualAddress else None
    if o is None:
        return []
    nf, nn, aof, aon, aoo = struct.unpack_from("<IIIII", img.data, o + 20)
    fo, no, oo = _rva_off(img, aof), _rva_off(img, aon), _rva_off(img, aoo)
    if fo is None or no is None or oo is None or nn > 2_000_000:
        return []
    out = []
    for i in range(nn):
        nrva = struct.unpack_from("<I", img.data, no + 4 * i)[0]
        ordi = struct.unpack_from("<H", img.data, oo + 2 * i)[0]
        if ordi >= nf:
            continue
        rva = struct.unpack_from("<I", img.data, fo + 4 * ordi)[0]
        so = _rva_off(img, nrva)
        if so is None:
            continue
        e = img.data.index(b"\0", so)
        out.append((rva, img.data[so:e].decode("latin-1")))
    return out


def bpl_compiler(path: Path) -> int | None:
    """Compiler version (``30`` for Delphi 10 Seattle) from the copyright string of the System unit."""
    try:
        m = _COMPILER.search(path.read_bytes())
    except OSError:
        return None
    return int(m.group(1)) if m else None


_RET = {"ret", "retf", "retn"}


def _sweep(md, img: _Pe, code: bytes, rva: int) -> tuple[list[tuple[int, int, str, str]], int]:
    """Linear sweep from ``rva``: [(offset, size, mnemonic, op_str)] and the end offset of the routine.
    The end is the first ``ret`` / unconditional jump that no earlier forward branch reaches past."""
    ins_list: list[tuple[int, int, str, str]] = []
    n = len(code)
    pos = 0
    far = 0                          # farthest forward branch target seen (offset)
    end = 0
    while pos < n:
        restart = -1
        stop = False
        for ins in md.disasm(code[pos:], rva + pos):
            off = ins.address - rva
            mn, ops = ins.mnemonic, ins.op_str
            if ins.size == 1 and ins.bytes[0] == 0xCC:
                stop = True
                break
            ins_list.append((off, ins.size, mn, ops))
            end = off + ins.size
            if mn in _RET:
                if end > far:
                    stop = True
                    break
                continue
            if mn[0] != "j" and not mn.startswith("loop"):
                continue
            t = _direct_target(ops)
            if t is not None:
                if end <= t - rva < n:
                    far = max(far, t - rva)
                if mn == "jmp" and end > far:
                    stop = True
                    break
                continue
            if mn != "jmp":
                continue
            # indirect jump: a jump table of relocated slots may follow in the code stream
            p = end
            while rva + p in img.relocs and p + img.relocs[rva + p] <= n:
                w = img.relocs[rva + p]
                slot = int.from_bytes(code[p:p + w], "little") - img.image_base - rva
                if 0 <= slot < n:
                    far = max(far, slot)
                p += w
            if p > end and far >= p and p < n:
                ins_list.append((end, p - end, "<table>", ""))
                end = restart = p
            else:
                stop = True
            break
        if stop or restart < 0:
            break
        pos = restart
    return ins_list, end


def _direct_target(ops: str) -> int | None:
    try:
        return int(ops, 0)
    except ValueError:
        return None


def _decode_exact(md, code: bytes, rva: int) -> list[tuple[int, int, str, str]]:
    """Linear decode of known routine bytes; an undecodable byte (data in the code stream) is skipped."""
    out: list[tuple[int, int, str, str]] = []
    pos, n = 0, len(code)
    while pos < n:
        last = pos
        for ins in md.disasm(code[pos:], rva + pos):
            out.append((ins.address - rva, ins.size, ins.mnemonic, ins.op_str))
            last = ins.address - rva + ins.size
        pos = last + 1
    return out


def _scan_routine(md, img: _Pe, rva: int, limit: int, exact: int | None = None) -> tuple[bytes, bytes] | None:
    """Dump and mask of the routine at ``rva``. ``exact``: its known size (``.pdata``); otherwise the end is
    found by a sweep, at most ``limit`` bytes."""
    off = _rva_off(img, rva)
    if off is None:
        return None
    if exact is not None:
        end = exact
        code = img.data[off:off + min(end, MAX_LEN + 16)]
        if end < MIN_LEN or len(code) < MIN_LEN:
            return None
        ins_list = _decode_exact(md, code, rva)
    else:
        code = img.data[off:off + min(limit, MAX_SWEEP)]
        if len(code) < MIN_LEN:
            return None
        ins_list, end = _sweep(md, img, code, rva)
        if end < MIN_LEN:
            return None
    n = min(end, MAX_LEN, len(code))
    dump = bytearray(code[:n])
    mask = bytearray(n)
    for off_i, size, mn, ops in ins_list:
        if off_i >= n:
            break
        if mn == "<table>":
            continue
        b = code[off_i:off_i + size]
        if mn == "call" or mn[0] == "j" or mn.startswith("loop"):
            t = _direct_target(ops)
            if t is not None and not (0 <= t - rva < end):
                w = 4 if (b[0] in (0xE8, 0xE9) or (b[0] == 0x0F and size == 6)) else 1
                for k in range(size - w, size):
                    if off_i + k < n:
                        mask[off_i + k] = 0xFF
        elif img.psize == 8 and "rip" in ops:
            _mask_rip(md, b, rva + off_i, rva, end, mask, off_i, n)
    if img.reloc_rvas is None:
        img.reloc_rvas = sorted(img.relocs)
    rr = img.reloc_rvas
    for j in range(bisect.bisect_left(rr, rva - 7), len(rr)):
        r = rr[j]
        if r >= rva + n:
            break
        for k in range(img.relocs[r]):
            if 0 <= r - rva + k < n:
                mask[r - rva + k] = 0xFF
    for i in range(n):
        if mask[i]:
            dump[i] = 0
    return bytes(dump), bytes(mask)


def _mask_rip(md, b: bytes, addr: int, rva: int, end: int, mask: bytearray, off_i: int, n: int) -> None:
    """Mask the disp32 of a RIP-relative operand unless it points inside the routine."""
    for ins in md.disasm(b, addr):
        if ins.disp_size != 4:
            return
        tgt = ins.address + ins.size + _rip_disp(ins)
        if rva <= tgt < rva + end:
            return
        for k in range(ins.disp_offset, ins.disp_offset + 4):
            if off_i + k < n:
                mask[off_i + k] = 0xFF
        return


def _rip_disp(ins) -> int:
    for op in ins.operands:
        if op.type == 3 and op.mem.base != 0:                   # X86_OP_MEM
            return op.mem.disp
    return ins.disp


def scan_bpl(path_str: str) -> tuple[int, list[tuple[str, bytes, bytes]]]:
    """(pointer size, [(Unit.Class.Method, dump, mask)]) of one package. Runs in worker processes."""
    try:
        import capstone
    except ImportError as e:                                    # pragma: no cover
        raise SigError("the build needs the capstone package (pip install capstone)") from e
    img = _read_pe(Path(path_str))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if img.psize == 8 else capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = False
    xsecs = [(va, va + max(vs, rs)) for va, vs, _r, rs, x in img.sections if x]
    funcs = img.funcs
    starts = {r for r, _n in img.exports} | {e for _s, e in xsecs}
    if funcs:
        starts |= set(funcs)
    bounds = sorted(starts)
    seen: dict[int, list[str]] = {}
    for rva, mangled in img.exports:
        if funcs is None:
            name = demangle(mangled)
        elif rva in funcs:
            name = itanium.demangle(mangled)
        else:                                   # 64-bit routine without unwind info (a leaf routine)
            name = itanium.demangle(mangled, need_params=True)
        if name is None or not any(s <= rva < e for s, e in xsecs):
            continue
        seen.setdefault(rva, []).append(name)
    out: list[tuple[str, bytes, bytes]] = []
    for rva, names in seen.items():
        i = bisect.bisect_right(bounds, rva)
        limit = (bounds[i] if i < len(bounds) else rva + MAX_SWEEP) - rva
        exact = funcs[rva] - rva if funcs and rva in funcs else None
        got = _scan_routine(md, img, rva, limit, exact)
        if got is None:
            continue
        for nm in sorted(set(names)):
            out.append((nm, got[0], got[1]))
    return img.psize, out


# -- database file ----------------------------------------------------------------------------

def write_sigdb(path: Path, compiler: int, psize: int, records: list[tuple[str, bytes, bytes]],
                meta: dict | None = None) -> None:
    """File layout: ``MAGIC; u32 header length; JSON header; zlib(records)``. A record is
    ``u16 name length; name; u32 size; code bytes; mask bytes`` (mask 0xFF = byte not compared)."""
    body = bytearray()
    for name, dump, mask in records:
        nb = name.encode("utf-8")
        body += struct.pack("<H", len(nb)) + nb + struct.pack("<I", len(dump)) + dump + mask
    head = json.dumps({"compiler": compiler, "bits": psize * 8, "count": len(records), **(meta or {})},
                      separators=(",", ":")).encode()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(MAGIC + struct.pack("<I", len(head)) + head + zlib.compress(bytes(body), 6))
    tmp.replace(path)


def read_sigdb_header(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            raw = f.read(len(MAGIC) + 4)
            if raw[:len(MAGIC)] != MAGIC:
                raise SigError(f"{path.name} is not a signature database")
            (n,) = struct.unpack("<I", raw[len(MAGIC):])
            if n > 65536:
                raise SigError(f"{path.name} is damaged")
            return json.loads(f.read(n))
    except (OSError, ValueError, struct.error) as e:
        raise SigError(f"cannot read {path.name}: {e}") from e


def read_sigdb(path: Path, label: str = "") -> idr.Kb:
    """Load a signature database into a matcher (``idr.Kb``). Raises ``idr.KbError`` when unreadable."""
    try:
        head = read_sigdb_header(path)
        raw = path.read_bytes()
        (n,) = struct.unpack_from("<I", raw, len(MAGIC))
        body = zlib.decompress(raw[len(MAGIC) + 4 + n:])
        kb = idr.Kb(label or path.stem)
        p = 0
        count = int(head["count"])
        kb.total = count
        for _ in range(count):
            (nl,) = struct.unpack_from("<H", body, p)
            name = body[p + 2:p + 2 + nl].decode("utf-8")
            p += 2 + nl
            (size,) = struct.unpack_from("<I", body, p)
            p += 4
            kb.add(name, body[p:p + size], body[p + size:p + 2 * size])
            p += 2 * size
        kb.finish()
        return kb
    except (SigError, OSError, zlib.error, struct.error, KeyError, UnicodeDecodeError) as e:
        raise idr.KbError(f"{path.name} is damaged ({e})") from e


# -- build ------------------------------------------------------------------------------------

@dataclass
class BuildResult:
    path: Path
    compiler: int
    psize: int
    packages: int
    routines: int
    names: int
    seconds: float


def install_packages(install: Path, psize: int) -> list[Path]:
    """Runtime packages of a Delphi install for a platform: the ``Redist`` folder of the platform
    (``win32`` / ``win64``), plus the RTL / VCL packages of ``bin`` / ``bin64`` the Redist folder lacks."""
    sub, extra = ("win64", "bin64") if psize == 8 else ("win32", "bin")
    found: dict[str, Path] = {}
    for folder in (install / "Redist" / sub, install / extra):
        try:
            for p in sorted(folder.glob("*.bpl")):
                if folder.name == extra and not _CORE.match(p.name):
                    continue
                found.setdefault(p.name.lower(), p)
        except OSError:
            continue
    return list(found.values())


def build(install: Path, out_dir: Path, psize: int = 4, progress: Callable[[str], None] | None = None,
          jobs: int = 4) -> BuildResult:
    """Build ``<compiler>-<bits>.sigdb`` in ``out_dir`` from the packages of a Delphi install."""
    t0 = time.time()
    pkgs = install_packages(install, psize)
    if not pkgs:
        raise SigError(f"no .bpl packages for {psize * 8}-bit in {install} "
                       f"(looked in Redist, bin)")
    comp = None
    for p in pkgs:
        comp = bpl_compiler(p)
        if comp:
            break
    if comp is None:
        raise SigError("no compiler version string found in the packages")
    say = progress or (lambda _m: None)
    merged: dict[tuple[str, bytes, bytes], None] = {}
    sizes = [p.stat().st_size for p in pkgs]
    order = sorted(range(len(pkgs)), key=lambda i: -sizes[i])      # big packages first
    done = 0
    if jobs > 1 and len(pkgs) > 1:
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            futs = [(i, ex.submit(scan_bpl, str(pkgs[i]))) for i in order]
            for i, fut in futs:
                try:
                    _ps, recs = fut.result()
                except Exception as e:  # noqa: BLE001
                    say(f"{pkgs[i].name}: skipped ({e})")
                    continue
                merged.update(dict.fromkeys(recs))
                done += 1
                say(f"{pkgs[i].name}: {len(recs)} routines")
    else:
        for i in order:
            try:
                _ps, recs = scan_bpl(str(pkgs[i]))
            except Exception as e:  # noqa: BLE001
                say(f"{pkgs[i].name}: skipped ({e})")
                continue
            merged.update(dict.fromkeys(recs))
            done += 1
            say(f"{pkgs[i].name}: {len(recs)} routines")
    records = list(merged)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{comp}-{psize * 8}.sigdb"
    write_sigdb(path, comp, psize, records,
                {"install": install.name, "packages": done, "built": time.strftime("%Y-%m-%d"), "format": 2})
    return BuildResult(path, comp, psize, done, len({(d, m) for _n, d, m in records}), len(records),
                       time.time() - t0)
