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

IDR_VERSION = 3                      # bump when matching or storage changes: projects recompute on open
VERSION_META = "idr_version"         # ``idr_version:<binary id>`` = ``IDR_VERSION:kb signature:candidates``
HITS_META = "idr_hits"               # ``idr_hits:<binary id>`` = lines ``<hex address>\t<names>``
INFO_META = "idr_info"               # ``idr_info:<binary id>`` = one line for humans

MIN_FIXED = 10                       # unmasked bytes a proc needs to be used (import thunks have 2)
MAX_COPIES = 3                       # functions of one binary that may match the same proc
SAMPLE = 2500                        # functions used to choose between knowledge bases
MAX_NAMES = 3                        # names listed for one function
MAX_HITS_PAYLOAD = 4_000_000         # characters of the hits meta value
MAX_KB_BYTES = 600_000_000
HEAD = 1024                          # bytes of a function read once; longer procs are read again
ANCHOR_MAX = 48                      # a proc is keyed by a window of fixed bytes starting before this offset
WINDOWS = (16, 12, 8, 6, 4)                 # window lengths, longest first
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
        if not m or int(m.group(2)) != psize * 8:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        if p.is_file() and st.st_size > 64:
            out.append(KbFile(p, f"sig{m.group(1)}-{m.group(2)}", m.group(1), True, st.st_size, True))
    return sorted(out, key=lambda f: int(f.year))


def kb_files(root: Path | None, psize: int, sig_dir: Path | None = None) -> list[KbFile]:
    """Knowledge base files for the pointer size, then the signature databases. For a year with both kb
    and syskb only the kb is listed (it holds the system units too). IDR files are sorted by year, 4-digit
    years after 1-digit ones."""
    sigs = sig_files(sig_dir, psize)
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


class Kb:
    """The code procs of one knowledge base, indexed by a window of unmasked bytes."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.procs: list[Proc] = []
        self.table: dict[tuple[int, bytes], list[int]] = {}
        self.combos: list[tuple[int, int]] = []
        self.total = 0                  # proc records in the file
        self.skipped = 0                # code procs dropped (too few unmasked bytes)

    def add(self, name: str, dump: bytes, reloc: bytes) -> None:
        n = len(dump)
        fixed = n - reloc.count(0xFF)
        if fixed < MIN_FIXED:
            self.skipped += 1
            return
        anchor = _anchor(reloc, n)
        if anchor is None:
            self.skipped += 1
            return
        a0, w = anchor
        keep = bytes(0 if r == 0xFF else 0xFF for r in reloc)
        self.procs.append(Proc(name, int.from_bytes(dump, "little"), int.from_bytes(keep, "little"), n))
        self.table.setdefault((a0, dump[a0:a0 + w]), []).append(len(self.procs) - 1)

    def finish(self) -> None:
        self.combos = sorted({(a0, len(k)) for a0, k in self.table})


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


def match_all(kb: Kb, img: Image, funcs: list[tuple[int, int | None]]) -> dict[int, list[str]]:
    """{entry: names} for the functions that match. A proc that matches more than MAX_COPIES functions
    is a common code shape (a wrapper around one call), not a routine of the runtime: it is dropped."""
    found: dict[int, list[int]] = {}
    copies: dict[int, int] = {}
    for entry, size in funcs:
        got = match_procs(kb, img, entry, size)
        if got:
            found[entry] = got
            for i in got:
                copies[i] = copies.get(i, 0) + 1
    out: dict[int, list[str]] = {}
    for entry, idxs in found.items():
        names = sorted({kb.procs[i].name for i in idxs if copies[i] <= MAX_COPIES}, key=_name_rank)
        if names:
            out[entry] = names
    return out


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


def stale(store: Store, binary: Binary, kb_dir: Path | None, sig_dir: Path | None = None) -> bool:
    """True when the hits were computed by another IDR_VERSION, from other knowledge base files or for
    another number of unnamed functions (the function list changed)."""
    files = kb_files(kb_dir, binary.pointer_size or 4, sig_dir)
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


def _pick(files: list[KbFile], img: Image, funcs: list[tuple[int, int | None]]
          ) -> tuple[str, dict[int, list[str]], list[str]]:
    """Names for the functions. The signature database of the binary's exact compiler version goes first;
    the knowledge bases (and signature databases of other versions) then name the functions it left
    unnamed. Returns (label, matches, notes)."""
    comp = compiler_version(img)
    exact = [f for f in files if f.sig and comp is not None and int(f.year) == comp]
    pool = [f for f in files if f not in exact]
    hits: dict[int, list[str]] = {}
    labels: list[str] = []
    notes: list[str] = []
    if exact:
        try:
            hits = match_all(load_kb(exact[0]), img, funcs)
            labels.append(exact[0].label)
            notes.append(f"{exact[0].label} {len(hits)}/{len(funcs)}")
        except KbError as e:
            notes.append(f"{exact[0].label}: {e}")
    if pool:
        rest = [x for x in funcs if x[0] not in hits] if hits else funcs
        f, more, n2 = _pick_idr(pool, img, rest, comp)
        notes.extend(n2)
        if f is not None and more:
            labels.append(f.label)
            for entry, names in more.items():
                hits.setdefault(entry, names)
        elif f is not None and not labels:
            labels.append(f.label)
    return "+".join(labels), hits, notes


def _pick_idr(files: list[KbFile], img: Image, funcs: list[tuple[int, int | None]], comp: int | None
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
    step = max(1, len(funcs) // SAMPLE)
    sample = funcs[::step]
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
           sig_dir: Path | None = None) -> tuple[str, int, int]:
    """Match the unnamed functions of a Delphi binary against the knowledge bases and store the result.
    Returns (knowledge base label or '', matched functions, candidates)."""
    files = kb_files(kb_dir, binary.pointer_size or 4, sig_dir)
    funcs = candidates(store, binary.id)
    sig = expected(files, len(funcs))
    label, hits, info = "", {}, "no knowledge base configured" if kb_dir is None else "no knowledge base files found"
    if files and funcs:
        img = Image.from_pe(artifact)
        if img is None:
            info = "not a PE file"
        else:
            label, hits, notes = _pick(files, img, funcs)
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
           sig_dir: Path | None = None) -> bool:
    """Derive the hits of a Delphi binary when missing or stale. Never raises; True when rewritten."""
    if binary.toolchain != "delphi" or not artifact.is_file():
        return False
    try:
        if not stale(store, binary, kb_dir, sig_dir):
            return False
        derive(store, binary, artifact, kb_dir, sig_dir)
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
