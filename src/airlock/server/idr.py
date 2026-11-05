"""Delphi RTL / VCL function names from an IDR knowledge base (DESIGN 11 "Delphi").

IDR (Interactive Delphi Reconstructor, MIT) ships knowledge bases (``kbNNNN.bin``, ``syskbNNNN.bin``):
the compiled code of the Delphi RTL and VCL units of one compiler version, with the bytes that depend
on the load address masked. The files are never part of this repository; ``idr_kb_dir`` in config.jsonc
points at a folder the user filled. Format notes (written from the format description, no code copied;
IDR is a format reference only):

* header: 24 byte signature (``IDR Knowledge Base File``), ``bool isMSIL``, ``i32 delphiVer``, ``u32 crc``,
  256 byte description, ``u32 kbVersion`` (2); the last 4 bytes of the file hold the offset of the section
  tables.
* section tables, in this order: modules, consts, types, vars, resource strings, procs. Each is
  ``i32 count; i32 maxSize`` and ``count`` entries ``{u32 offset; u32 size; i32 modId; i32 namId}``
  (16 bytes; ``modId`` / ``namId`` are sort orders, entry ``i`` is the record with ID ``i``).
* module record: ``u16 id; u16 nameLen; name\\0 ...``.
* proc record: ``u16 moduleId; u16 nameLen; name\\0; u8 embedded; u8 dumpType ('C' code, 'D' data);
  u8 methodKind; u8 callKind; i32 vproc; u16 typeLen; type\\0; u32 dumpTotal; u32 dumpSize;
  u32 fixupCount; dump[dumpSize]; relocs[dumpSize]; fixups ...``. A relocs byte of ``0xFF`` marks a dump
  byte that depends on the load address (not compared). The same layout serves 32- and 64-bit files.

Matching: a function whose bytes equal a proc dump on every unmasked byte gets the proc's name as a
hint. Procs with few unmasked bytes are skipped, several procs can match one function (all names are
listed). The result is stored as meta (``idr_hits:<id>``, one ``address<TAB>name`` line per function);
nothing is renamed in Ghidra and no table is added.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import re
import struct
import threading
from dataclasses import dataclass
from pathlib import Path

from airlock.index.store import Binary, Store
from airlock.server.cpp import Image

log = logging.getLogger("airlock")

IDR_VERSION = 9               # bump when matching or storage changes: projects recompute on open
VERSION_META = "idr_version"         # ``idr_version:<binary id>`` = ``IDR_VERSION:kb signature:candidates``
HITS_META = "idr_hits"               # ``idr_hits:<binary id>`` = lines ``<hex address>\t<names>``
INFO_META = "idr_info"               # ``idr_info:<binary id>`` = one line for humans

MIN_FIXED = 10                       # unmasked bytes a proc needs to be used (import thunks have 2)
MAX_COPIES = 3                       # functions of one binary that may match the same proc ...
LONG_SHAPE = 64                      # ... unless it has this many compared bytes
GENERIC_MIN = 16                     # ... or is a generic template (``TList<T>.Add``) with this many
SAMPLE = 2500                        # functions used to choose between knowledge bases
MAX_NAMES = 3                        # names listed for one function
MAX_HITS_PAYLOAD = 4_000_000         # characters of the hits meta value
MAX_KB_BYTES = 600_000_000
HEAD = 1024                          # bytes of a function read once; longer procs are read again
ANCHOR_MAX = 48                      # a proc is keyed by a window of fixed bytes starting before this offset
WINDOWS = (16, 12, 8, 6, 4)                 # window lengths, longest first
CTX_MIN_VOTES = 1                    # callers that must give a callee the same name (call-context pass)
PAD_SLACK = 16                       # a proc dump ends with up to 15 padding bytes that Ghidra leaves out

_KB_NAME = re.compile(r"^(sys)?kb(\d+)\.bin$", re.IGNORECASE)
_UNNAMED = re.compile(r"^(?:thunk_)?FUN_[0-9a-fA-F]+$")
_SIGNATURE = b"IDR Knowledge Base File"
_OLD_SIGNATURE = b"IDD Knowledge Base File"


class KbError(ValueError):
    """A knowledge base file that cannot be read."""


# -- files ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class KbFile:
    path: Path
    label: str           # ``kb2010`` / ``syskb2012``
    year: str            # ``2010``
    full: bool           # kb (RTL + VCL) rather than syskb (system units only)
    size: int
    sig: bool = False    # signature database built from a local Delphi install (``year`` = compiler version)
    rtti: bool = False   # RTTI consensus database (``delphirtti``), a sigdb file named ``rtti-<compiler>-<bits>``
    warp: bool = False   # WARP library: delphinja's ``delphi-rtl-<stem>.warp`` (32-bit) or an own ``airlock-rtl-win<bits>.warp``


def kb_folders(root: Path, psize: int) -> list[Path]:
    """Folders searched for the knowledge bases of a pointer size: 64-bit files must be in ``x64`` (or
    ``win64``), 32-bit ones in the folder itself or in ``x86`` / ``win32``."""
    if psize == 8:
        return [root / "x64", root / "win64"]
    return [root, root / "x86", root / "win32"]


def sig_files(sig_dir: Path | None, psize: int) -> list[KbFile]:
    """Signature databases (``<compiler>-<32|64>.sigdb``) of the pointer size, sorted by compiler."""
    from airlock.server import delphisigs
    out: list[KbFile] = []
    try:
        names = sorted(sig_dir.iterdir()) if sig_dir is not None else []
    except OSError:
        return []
    for p in names:
        m = delphisigs.SIG_NAME.match(p.name)
        r = None if m else re.match(r"^rtti-(\d+)-(32|64)\.sigdb$", p.name)
        m = m or r
        if not m or int(m.group(2)) != psize * 8:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        if p.is_file() and st.st_size > 64:
            out.append(KbFile(p, f"{'rtti' if r else 'sig'}{m.group(1)}-{m.group(2)}", m.group(1), True, st.st_size,
                              True, r is not None))
    return sorted(out, key=lambda f: (int(f.year), f.rtti))


def warp_files(warp_dir: Path | None, psize: int) -> list[KbFile]:
    """WARP libraries of the pointer size: delphinja's ``delphi-rtl-*.warp`` (32-bit only) and the own
    ``airlock-rtl-win32|win64.warp`` (``delphi-sigs warp-build``)."""
    from airlock.server import warp
    out: list[KbFile] = []
    try:
        names = sorted(warp_dir.iterdir()) if warp_dir is not None else []
    except OSError:
        return []
    for p in names:
        stem = warp.warp_stem(p)
        try:
            size = p.stat().st_size
        except OSError:
            continue
        own = stem is not None and stem.startswith("win")
        if own and not warp.own_stem(stem, psize) or (psize == 8 and not own):
            continue
        if stem and p.is_file() and size > 64:
            out.append(KbFile(p, f"warp-{stem}", stem, False, size, warp=True))
    return out


def kb_files(root: Path | None, psize: int, sig_dir: Path | None = None,
             warp_dir: Path | None = None) -> list[KbFile]:
    """Knowledge base files for the pointer size, then the signature databases and WARP libraries. For a
    year with both kb and syskb only the kb is listed (it holds the system units too). IDR files are sorted
    by year, 4-digit years after 1-digit ones."""
    sigs = sig_files(sig_dir, psize) + warp_files(warp_dir, psize)
    if root is None:
        return sigs
    by_year: dict[str, KbFile] = {}
    for folder in kb_folders(root, psize):
        try:
            names = sorted(folder.iterdir())
        except OSError:
            continue
        for p in names:
            m = _KB_NAME.match(p.name)
            if not m:
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            if not p.is_file() or st.st_size < 400 or st.st_size > MAX_KB_BYTES:
                continue
            f = KbFile(p, p.stem.lower(), m.group(2), m.group(1) is None, st.st_size)
            old = by_year.get(f.year)
            if old is None or (f.full and not old.full):
                by_year[f.year] = f
    return sorted(by_year.values(), key=lambda f: (len(f.year), f.year)) + sigs


def kb_signature(files: list[KbFile]) -> str:
    if not files:
        return "none"
    h = hashlib.sha1()
    for f in files:
        h.update(f"{f.label}:{f.size};".encode())
    return h.hexdigest()[:10]


# -- reader -----------------------------------------------------------------------------------

@dataclass
class Proc:
    name: str            # ``Unit.Proc``
    dump: int            # code bytes as a little-endian integer
    keep: int            # 0xFF for compared bytes, 0 for masked ones
    size: int
    fixed: int = 0       # compared bytes
    calls: tuple = ()    # ((offset of the rel32 operand, opcode 0xE8 / 0xE9, callee name), ...) of the reference


class Kb:
    """The code procs of one knowledge base, indexed by a window of unmasked bytes."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.procs: list[Proc] = []
        self.table: dict[tuple[int, bytes], list[int]] = {}
        self.combos: list[tuple[int, int]] = []
        self.total = 0                  # proc records in the file
        self.skipped = 0                # code procs dropped (too few unmasked bytes)

    def add(self, name: str, dump: bytes, reloc: bytes, calls: tuple = ()) -> None:
        n = len(dump)
        fixed = n - reloc.count(0xFF)
        anchor = _anchor(reloc, n) if fixed >= MIN_FIXED else None
        if anchor is None:
            self.skipped += 1
            return
        a0, w = anchor
        keep = bytes(0 if r == 0xFF else 0xFF for r in reloc)
        self.procs.append(Proc(name, int.from_bytes(dump, "little"), int.from_bytes(keep, "little"), n, fixed,
                               calls))
        self.table.setdefault((a0, dump[a0:a0 + w]), []).append(len(self.procs) - 1)

    def finish(self) -> None:
        self.combos = sorted({(a0, len(k)) for a0, k in self.table})


def usable(reloc: bytes) -> bool:
    """True when a proc with this mask is kept by ``Kb.add`` (enough compared bytes and an anchor window).
    Import stubs (``jmp [mem]``, 2 compared bytes) are not."""
    n = len(reloc)
    return n - reloc.count(0xFF) >= MIN_FIXED and _anchor(reloc, n) is not None


def _anchor(reloc: bytes, n: int) -> tuple[int, int] | None:
    """(offset, length) of the first run of at least 4 unmasked bytes that starts before ANCHOR_MAX;
    the length is the largest of WINDOWS that fits in the run."""
    run = 0
    for i in range(min(n, ANCHOR_MAX + 8)):
        if reloc[i] == 0xFF:
            run = 0
            continue
        run += 1
        if run >= 4:
            start = i - run + 1
            if start > ANCHOR_MAX:
                return None
            j = i + 1
            while j < n and reloc[j] != 0xFF and j - start < WINDOWS[0]:
                j += 1
            length = j - start
            for w in WINDOWS:
                if length >= w:
                    return start, w
            return start, 4
    return None


def _u16(d: memoryview, p: int) -> int:
    return struct.unpack_from("<H", d, p)[0]


def _u32(d: memoryview, p: int) -> int:
    return struct.unpack_from("<I", d, p)[0]


def _cstr(d: memoryview, p: int, n: int) -> str:
    return bytes(d[p:p + n]).decode("latin-1")


def read_kb(path: Path, label: str = "") -> Kb:
    """Parse the code procs of a knowledge base file. Raises KbError for anything unexpected."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise KbError(f"cannot read {path.name}: {e.strerror or e}") from e
    d = memoryview(raw)
    try:
        return _parse(d, label or path.stem)
    except (struct.error, IndexError, ValueError) as e:
        raise KbError(f"{path.name} is damaged ({e})") from e


def _parse(d: memoryview, label: str) -> Kb:
    if len(d) < 300 or bytes(d[:24]).split(b"\0")[0] not in (_SIGNATURE, _OLD_SIGNATURE):
        raise KbError("not an IDR knowledge base file")
    if bytes(d[:24]).startswith(_OLD_SIGNATURE) or _u32(d, 289) != 2:
        raise KbError("only knowledge base format 2 is supported")
    pos = _u32(d, len(d) - 4)
    if pos < 293 or pos >= len(d) - 4:
        raise KbError("bad section table offset")
    tables: list[list[tuple[int, int]]] = []
    for _ in range(6):
        count = _u32(d, pos)
        pos += 8
        if count > 5_000_000 or pos + 16 * count > len(d):
            raise KbError("bad section size")
        ents = [struct.unpack_from("<II", d, pos + 16 * i) for i in range(count)]
        pos += 16 * count
        tables.append(ents)
    modules = {}
    for i, (off, size) in enumerate(tables[0]):
        if off + 4 > len(d):
            continue
        n = _u16(d, off + 2)
        modules[i] = _cstr(d, off + 4, n)
    kb = Kb(label)
    kb.total = len(tables[5])
    for off, size in tables[5]:
        if off + size > len(d) or size < 28:
            continue
        p = off
        mod = _u16(d, p)
        n = _u16(d, p + 2)
        name = _cstr(d, p + 4, n)
        p += 4 + n + 1
        dump_type = d[p + 1]
        p += 8
        n = _u16(d, p)
        p += 2 + n + 1
        p += 4                                   # dumpTotal
        dsz = _u32(d, p)
        p += 8                                   # dumpSize, fixupCount
        if dump_type != 0x43 or dsz == 0 or p + 2 * dsz > off + size:
            continue
        unit = modules.get(mod, "")
        kb.add(f"{unit}.{name}" if unit else name, bytes(d[p:p + dsz]), bytes(d[p + dsz:p + 2 * dsz]))
    kb.finish()
    return kb


_CACHE: dict[tuple[str, int, int], Kb] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 3


def load_kb(f: KbFile) -> Kb:
    """``read_kb`` with a small per-process cache (a project analyses several binaries)."""
    try:
        st = f.path.stat()
    except OSError as e:
        raise KbError(f"cannot read {f.path.name}: {e.strerror or e}") from e
    key = (str(f.path), st.st_size, st.st_mtime_ns)
    with _CACHE_LOCK:
        kb = _CACHE.get(key)
    if kb is None:
        if f.sig:
            from airlock.server import delphisigs
            kb = delphisigs.read_sigdb(f.path, f.label)
        else:
            kb = read_kb(f.path, f.label)
        with _CACHE_LOCK:
            while len(_CACHE) >= _CACHE_MAX:
                _CACHE.pop(next(iter(_CACHE)))
            _CACHE[key] = kb
    return kb


# -- matching ---------------------------------------------------------------------------------

def _name_rank(name: str) -> tuple[bool, bool, int, str]:
    """Plain names before generic instances, RTL / VCL units before others, short before long."""
    return ("<" in name, not name.startswith(("System.", "Vcl.", "Winapi.", "SysUtils.", "Classes.")),
            len(name), name)


def match_procs(kb: Kb, img: Image, entry: int, size: int | None) -> list[int]:
    """Indexes of the procs whose unmasked bytes equal the code at ``entry``."""
    head = img.read(entry, HEAD) or img.read(entry, 64)
    if head is None:
        return []
    out: list[int] = []
    seen: set[int] = set()
    for a0, w in kb.combos:
        cand = kb.table.get((a0, head[a0:a0 + w]))
        if not cand:
            continue
        for idx in cand:
            if idx in seen:
                continue
            seen.add(idx)
            p = kb.procs[idx]
            if size is not None and size < p.size - PAD_SLACK:
                continue
            code = head[:p.size] if p.size <= len(head) else img.read(entry, p.size)
            if code is not None and len(code) == p.size and (int.from_bytes(code, "little") ^ p.dump) & p.keep == 0:
                out.append(idx)
    return out


def _many_ok(p: Proc) -> bool:
    """A proc that may match more than MAX_COPIES functions of one binary."""
    return p.fixed >= LONG_SHAPE or ("<" in p.name and p.fixed >= GENERIC_MIN)


def match_all(kb: Kb, img: Image, funcs: list[tuple[int, int | None]]) -> dict[int, list[str]]:
    """{entry: names} for the functions that match. A proc that matches more than MAX_COPIES functions
    is usually a common code shape (a wrapper around one call), not a routine of the runtime: it is dropped.
    Two kinds of proc may match many functions and are kept: a generic template (``TList<T>.Add``: one
    instance per element type) with at least ``GENERIC_MIN`` compared bytes, and a long shape
    (``LONG_SHAPE`` compared bytes: such code is not a wrapper). A generic with fewer bytes is a stub that
    thousands of program functions share.
    Measured on programs with a map file as truth and on two real programs (DESIGN 11): the long and generic
    procs add many named routines at a similar share of right names, the other procs add program methods that
    only look like runtime code."""
    return _match(kb, img, funcs)[0]


def _match(kb: Kb, img: Image, funcs: list[tuple[int, int | None]]
           ) -> tuple[dict[int, list[str]], dict[int, list[int]]]:
    """(``match_all`` result, {entry: indexes of the procs behind those names})."""
    found: dict[int, list[int]] = {}
    copies: dict[int, int] = {}
    for entry, size in funcs:
        got = match_procs(kb, img, entry, size)
        if got:
            found[entry] = got
            for i in got:
                copies[i] = copies.get(i, 0) + 1
    out: dict[int, list[str]] = {}
    kept: dict[int, list[int]] = {}
    for entry, idxs in found.items():
        ok = [i for i in idxs if copies[i] <= MAX_COPIES or _many_ok(kb.procs[i])]
        names = sorted({kb.procs[i].name for i in ok}, key=_name_rank)
        if names:
            out[entry] = names
            kept[entry] = ok
    return out, kept


def call_context(kb: Kb, img: Image, entries: set[int], kept: dict[int, list[int]], known: set[int]
                 ) -> dict[int, list[str]]:
    """Names for the callees of named functions. A routine under ``MIN_FIXED`` compared bytes cannot be
    matched by its code, but the database remembers, for each reference routine, the name of every callee
    at the offset of its ``call`` / ``jmp`` operand. The code of a matched function equals the reference on
    every compared byte, and the opcode byte before the operand is one of them: the instruction at that
    offset is the same call, so its target plays the same role as the reference callee. The target gets the
    callee's name when it is an unnamed function (``entries`` minus ``known``) and all callers (at least
    ``CTX_MIN_VOTES``) agree; one disagreeing name rejects it. Returns {entry: [name]}."""
    if not any(p.calls for p in kb.procs):
        return {}
    mask = (1 << (8 * img.psize)) - 1
    votes: dict[int, dict[str, int]] = {}
    for entry, idxs in kept.items():
        at: dict[tuple[int, int], set[str]] = {}
        for i in idxs:
            for off, op, name in kb.procs[i].calls:
                at.setdefault((off, op), set()).add(name)
        for (off, op), names in at.items():
            if len(names) != 1:                      # aliases of one routine disagree here
                continue
            raw = img.read(entry + off - 1, 5)
            if raw is None or raw[0] != op:
                continue
            tgt = (entry + off + 4 + int.from_bytes(raw[1:], "little", signed=True)) & mask
            if tgt in entries and tgt not in known and tgt != entry:
                v = votes.setdefault(tgt, {})
                nm = next(iter(names))
                v[nm] = v.get(nm, 0) + 1
    return {t: [next(iter(v))] for t, v in votes.items() if len(v) == 1 and sum(v.values()) >= CTX_MIN_VOTES}


def match_with_context(kb: Kb, img: Image, funcs: list[tuple[int, int | None]]
                       ) -> tuple[dict[int, list[str]], dict[int, list[str]]]:
    """(names by code, names by call context) for the functions; the second never repeats the first."""
    names, kept = _match(kb, img, funcs)
    return names, call_context(kb, img, {e for e, _s in funcs}, kept, set(names))


# -- store ------------------------------------------------------------------------------------

def _key(prefix: str, binary_id: int) -> str:
    return f"{prefix}:{binary_id}"


def candidates(store: Store, binary_id: int) -> list[tuple[int, int | None]]:
    """(entry, size) of the unnamed functions of a binary."""
    rows = store.db.execute(
        "SELECT entry, size, name FROM function WHERE binary_id=? AND space='ram' AND is_external=0 AND "
        "name_state='auto' ORDER BY entry", (binary_id,)).fetchall()
    return [(r[0], r[1] or None) for r in rows if _UNNAMED.match(r[2])]


def expected(files: list[KbFile], ncand: int) -> str:
    return f"{IDR_VERSION}:{kb_signature(files)}:{ncand}"


def stale(store: Store, binary: Binary, kb_dir: Path | None, sig_dir: Path | None = None,
          warp_dir: Path | None = None) -> bool:
    """True when the hits were computed by another IDR_VERSION, from other knowledge base files or for
    another number of unnamed functions (the function list changed)."""
    files = kb_files(kb_dir, binary.pointer_size or 4, sig_dir, warp_dir)
    cur = store.get_meta(_key(VERSION_META, binary.id))
    if not files:                      # nothing configured: only a former result has to be cleared
        return cur is not None and not cur.startswith(f"{IDR_VERSION}:none:")
    try:
        n = len(candidates(store, binary.id))
    except Exception:  # noqa: BLE001  no function table yet
        return False
    return cur != expected(files, n)


_COMPILER = re.compile(rb"(?:Embarcadero|CodeGear) Delphi for Win(?:32|64) compiler version (\d+)\.(\d+)")
# compiler version of the Delphi release each knowledge base file is named after
KB_COMPILER = {"2": 9, "3": 10, "4": 12, "5": 13, "6": 14, "7": 15, "2005": 17, "2006": 18, "2007": 19,
               "2009": 20, "2010": 21, "2011": 22, "2012": 23, "2013": 24, "2014": 25}


def compiler_version(img: Image) -> int | None:
    """The compiler version (``30`` for Delphi 10 Seattle) from the copyright string that the System
    unit of Delphi 2009 and later keeps in the binary; None when it is absent."""
    for s in img.sections:
        m = _COMPILER.search(s.data)
        if m:
            return int(m.group(1))
    return None


def _warp_stems(comp: int) -> list[str]:
    from airlock.server import warp
    return warp.library_stems(comp)


def _pick(files: list[KbFile], img: Image, funcs: list[tuple[int, int | None]],
          instances: dict[str, set[str]] | None = None) -> tuple[str, dict[int, list[str]], list[str]]:
    """Names for the functions. The signature database of the binary's exact compiler version goes first;
    the knowledge bases (and signature databases of other versions) then name the functions it left
    unnamed. ``instances``: the generic classes of the program (``warp.instance_args``), which give WARP's
    ``TList<T>`` names their real type arguments. Returns (label, matches, notes)."""
    comp = compiler_version(img)
    exact = [f for f in files if f.sig and not f.rtti and comp is not None and int(f.year) == comp]
    rtti = [f for f in files if f.rtti and comp is not None and int(f.year) == comp]
    warps = [f for f in files if f.warp]
    pool = [f for f in files if f not in exact and f not in rtti and not f.warp]
    hits: dict[int, list[str]] = {}
    labels: list[str] = []
    notes: list[str] = []
    for tier in (exact[:1], rtti[:1]):           # exact-version database, then the RTTI consensus database
        if not tier:
            continue
        rest = [x for x in funcs if x[0] not in hits] if hits else funcs
        try:
            got, ctx = match_with_context(load_kb(tier[0]), img, rest)
            for entry, names in got.items():
                hits.setdefault(entry, names)
            for entry, names in ctx.items():
                hits.setdefault(entry, names)
            labels.append(tier[0].label)
            notes.append(f"{tier[0].label} {len(got)}/{len(rest)}" + (f" +{len(ctx)} by calls" if ctx else ""))
        except KbError as e:
            notes.append(f"{tier[0].label}: {e}")
    score = [x for x in funcs if x[0] not in hits] if hits else funcs   # the IDR file is chosen on these,
    if warps:                                    # whatever WARP names; then the WARP libraries of the compiler version
        stems = _warp_stems(comp) if comp is not None else []
        use = [f for f in warps if f.year in stems or f.year.startswith("win")]
        rest = score
        if use and rest:
            try:
                from airlock.server import warp
                got = warp.match_functions([warp.load_lib(f.path) for f in use], img, rest)
                for entry, names in got.items():
                    hits.setdefault(entry, warp.refine_generics(names, instances) if instances else names)
                labels.append("warp")
                notes.append(f"warp {len(got)}/{len(rest)}")
            except Exception as e:  # noqa: BLE001  WarpError, capstone missing, unreadable file
                notes.append(f"warp: {e}")
    if pool:
        rest = [x for x in funcs if x[0] not in hits] if hits else funcs
        f, more, n2 = _pick_idr(pool, img, rest, comp, score)
        notes.extend(n2)
        if f is not None and more:
            labels.append(f.label)
            for entry, names in more.items():
                hits.setdefault(entry, names)
        elif f is not None and not labels:
            labels.append(f.label)
    return "+".join(labels), hits, notes


def _generic_instances(store: Store, binary_id: int) -> dict[str, set[str]]:
    """Generic classes of the program from its RTTI (``{Unit.TBase: {type arguments}}``)."""
    from airlock.server import warp
    try:
        rows = store.db.execute("SELECT unit, name FROM dl_class WHERE binary_id=? AND name LIKE '%<%>'",
                                (binary_id,)).fetchall()
    except Exception:  # noqa: BLE001  no class table yet
        return {}
    return warp.instance_args([(r[0], r[1]) for r in rows])


def _pick_idr(files: list[KbFile], img: Image, funcs: list[tuple[int, int | None]], comp: int | None,
              score: list[tuple[int, int | None]] | None = None
              ) -> tuple[KbFile | None, dict[int, list[str]], list[str]]:
    """The knowledge base of the binary's compiler version when there is one, else the one with the most
    matching functions, judged on a sample of the functions; the winner then runs over all of them.
    Returns (file, matches, notes)."""
    exact = [f for f in files if KB_COMPILER.get(f.year) == comp] if comp is not None else []
    note0 = [] if comp is None else [f"compiler {comp}" + ("" if exact else ", no knowledge base for it")]
    if exact:
        try:
            return exact[0], match_all(load_kb(exact[0]), img, funcs), note0
        except KbError as e:
            note0.append(f"{exact[0].label}: {e}")
    pool = score if score is not None else funcs      # choose on the functions no earlier tier named
    step = max(1, len(pool) // SAMPLE)
    sample = pool[::step]
    best: tuple[KbFile, Kb, int] | None = None
    notes: list[str] = note0
    for f in files:
        try:
            kb = load_kb(f)
        except KbError as e:
            notes.append(f"{f.label}: {e}")
            continue
        n = len(match_all(kb, img, sample)) if len(files) > 1 else 1
        notes.append(f"{f.label} {n}/{len(sample)}")
        if best is None or n >= best[2]:                 # a tie goes to the newer file
            best = (f, kb, n)
    if best is None:
        return None, {}, notes
    return best[0], match_all(best[1], img, funcs), notes


def derive(store: Store, binary: Binary, artifact: Path, kb_dir: Path | None,
           sig_dir: Path | None = None, warp_dir: Path | None = None) -> tuple[str, int, int]:
    """Match the unnamed functions of a Delphi binary against the knowledge bases and store the result.
    Returns (knowledge base label or '', matched functions, candidates)."""
    files = kb_files(kb_dir, binary.pointer_size or 4, sig_dir, warp_dir)
    funcs = candidates(store, binary.id)
    sig = expected(files, len(funcs))
    label, hits, info = "", {}, "no knowledge base configured" if kb_dir is None else "no knowledge base files found"
    if files and funcs:
        img = Image.from_pe(artifact)
        if img is None:
            info = "not a PE file"
        else:
            label, hits, notes = _pick(files, img, funcs, _generic_instances(store, binary.id))
            info = (f"{label}: {len(hits)} of {len(funcs)} unnamed functions named; tried " + ", ".join(notes)
                    if label else "; ".join(notes))
    elif files:
        info = "no unnamed functions"
    lines = []
    size = 0
    for entry in sorted(hits):
        names = hits[entry]
        text = " | ".join(names[:MAX_NAMES]) + (f" (+{len(names) - MAX_NAMES})" if len(names) > MAX_NAMES else "")
        line = f"{entry:x}\t{text}"
        size += len(line) + 1
        if size > MAX_HITS_PAYLOAD:
            break
        lines.append(line)
    with store.db:
        store.set_meta(_key(HITS_META, binary.id), "\n".join(lines))
        store.set_meta(_key(INFO_META, binary.id), info)
        store.set_meta(_key(VERSION_META, binary.id), sig)
    return label, len(lines), len(funcs)


def ensure(store: Store, binary: Binary, artifact: Path, kb_dir: Path | None,
           sig_dir: Path | None = None, warp_dir: Path | None = None) -> bool:
    """Derive the hits of a Delphi binary when missing or stale. Never raises; True when rewritten."""
    if binary.toolchain != "delphi" or not artifact.is_file():
        return False
    try:
        if not stale(store, binary, kb_dir, sig_dir, warp_dir):
            return False
        derive(store, binary, artifact, kb_dir, sig_dir, warp_dir)
        return True
    except Exception as e:  # noqa: BLE001  an extra; the binary stays usable
        log.warning("IDR names of %s failed: %s", binary.name, e)
        return False


# -- hits -------------------------------------------------------------------------------------

@functools.lru_cache(maxsize=8)
def _parse_hits(text: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for ln in text.splitlines():
        a, _t, names = ln.partition("	")
        try:
            out[int(a, 16)] = names
        except ValueError:
            continue
    return out


def hits(store: Store, binary_id: int) -> dict[int, str]:
    """{entry: names} from the meta value (the parsed text is cached by its content)."""
    return _parse_hits(store.get_meta(_key(HITS_META, binary_id)) or "")


def hint_for(store: Store, binary_id: int, entry: int) -> list[str]:
    names = hits(store, binary_id).get(entry)
    return [f"idr: {names}"] if names else []


def hit_addrs(store: Store, binary_id: int) -> set[int]:
    return set(hits(store, binary_id))


def info(store: Store, binary_id: int) -> str:
    return store.get_meta(_key(INFO_META, binary_id)) or ""
