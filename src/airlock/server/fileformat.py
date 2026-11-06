"""Raw file inspection without Ghidra: OLE streams, hexdump, diff, record guessing (DESIGN 6).

Pure functions over byte sources; the tool module (tools/fileformat.py) resolves paths and pages
the output. Everything here is memory-bounded: files are read in chunks or capped windows.
"""

from __future__ import annotations

import math
from bisect import bisect_right
import operator
import random
import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

import olefile

from airlock.server import recdetect

CHUNK = 1 << 20           # diff compare unit
SUB = 4096                # diff refine unit inside a differing chunk
GAP = 8                   # changed ranges closer than this many bytes are merged
CONTEXT = 4               # context bytes before/after a changed range
MAX_RANGES = 4000         # ranges kept per compared pair; the rest is only counted
MAX_SHOWN_BYTES = 16      # bytes of a changed range shown per side
MAX_DUMP = 16 * 1024      # bytes rendered by one hexdump / ole stream call
GUESS_WINDOW = 1 << 20    # bytes analysed by record_guess
STRIDE_SAMPLE = 32 * 1024
MAX_STRIDE = 512


class Src(Protocol):
    size: int

    def read(self, off: int, n: int) -> bytes: ...


class FileSrc:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.size = path.stat().st_size

    def read(self, off: int, n: int) -> bytes:
        with open(self.path, "rb") as f:
            f.seek(off)
            return f.read(n)


class BytesSrc:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    def read(self, off: int, n: int) -> bytes:
        return self.data[off:off + n]


def hx(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


# -- hexdump -----------------------------------------------------------------------------

def hexdump_lines(data: bytes, base: int) -> list[str]:
    out = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        out.append(f"0x{base + i:08x}  {hx(row):<47}  |{asc}|")
    return out


# -- OLE ---------------------------------------------------------------------------------

def is_ole(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == olefile.MAGIC
    except OSError:
        return False


def esc_name(s: str) -> str:
    return "".join(c if c >= " " and c != "\x7f" else f"\\x{ord(c):02x}" for c in s)


_ESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def unesc_name(s: str) -> str:
    return _ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)


def disp_path(parts: list[str]) -> str:
    return "/".join(["Root"] + [esc_name(p) for p in parts])


def ole_entries(ole: olefile.OleFileIO) -> tuple[list[tuple[list[str], int]], list[list[str]]]:
    """(streams with sizes, storages), each as component lists, in directory order."""
    streams = [(p, ole.get_size(p)) for p in ole.listdir(streams=True, storages=False)]
    storages = ole.listdir(streams=False, storages=True)
    return streams, storages


def find_stream(ole: olefile.OleFileIO, name: str) -> list[str] | None:
    """Resolve a user-given stream path (``Root/`` optional, ``\\x05`` escapes) to components."""
    want = unesc_name(name.strip().replace("\\\\", "\\"))
    parts = [p for p in want.replace("\\", "/").split("/") if p] if "\\x" not in name else \
        [p for p in want.split("/") if p]
    if parts and parts[0].lower() == "root":
        parts = parts[1:]
    for cand in ole.listdir(streams=True, storages=False):
        if cand == parts or [c.lower() for c in cand] == [p.lower() for p in parts]:
            return cand
    return None


def ole_tree_lines(path: Path) -> list[str] | str:
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as e:  # noqa: BLE001
        return f"error not_ole: {path.name} is not an OLE compound file ({type(e).__name__})."
    try:
        streams, storages = ole_entries(ole)
        total = sum(s for _, s in streams)
        out = [f"ole {path.name} {len(streams)} streams, {len(storages)} storages, "
               f"{total} stream bytes, file {path.stat().st_size} bytes"]
        rows = [(disp_path(p) + "/", None) for p in storages] + [(disp_path(p), s) for p, s in streams]
        rows.sort(key=lambda r: r[0].lower())
        out += [f"{n} (storage)" if s is None else f"{n} {s}" for n, s in rows]
        return out
    finally:
        ole.close()


def read_ole_stream(path: Path, name: str, cap: int = 256 << 20) -> bytes | str:
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception:  # noqa: BLE001
        return f"error not_ole: {path.name} is not an OLE compound file."
    try:
        parts = find_stream(ole, name)
        if parts is None:
            have = [disp_path(p) for p in ole.listdir(streams=True, storages=False)]
            more = f", +{len(have) - 12} more" if len(have) > 12 else ""
            return f"error not_found: no stream '{name}' in {path.name} (have: {', '.join(have[:12]) or 'none'}{more})."
        if ole.get_size(parts) > cap:
            return f"error too_big: stream {disp_path(parts)} is over {cap >> 20} MiB."
        return ole.openstream(parts).read()
    finally:
        ole.close()


def ole_stream_map(path: Path) -> dict[str, list[str]] | None:
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception:  # noqa: BLE001
        return None
    try:
        return {disp_path(p): p for p in ole.listdir(streams=True, storages=False)}
    finally:
        ole.close()


# -- diff --------------------------------------------------------------------------------

@dataclass
class DiffRange:
    start: int
    end: int          # exclusive
    a_only: bool = False   # past the end of b
    b_only: bool = False   # past the end of a


@dataclass
class DiffResult:
    ranges: list[DiffRange]
    changed_bytes: int
    range_count: int      # including ranges not kept
    truncated: bool


def _diff_positions(a: bytes, b: bytes, base: int) -> Iterator[int]:
    n = min(len(a), len(b))
    for s in range(0, n, SUB):
        x, y = a[s:s + SUB], b[s:s + SUB]
        if x == y:
            continue
        for i in (i for i, (p, q) in enumerate(zip(x, y)) if p != q):
            yield base + s + i


def diff_sources(a: Src, b: Src, gap: int = GAP) -> DiffResult:
    ranges: list[DiffRange] = []
    count = 0
    changed = 0
    cur_s = cur_e = -1
    truncated = False

    def close() -> None:
        nonlocal count, truncated
        if cur_s < 0:
            return
        count += 1
        if len(ranges) < MAX_RANGES:
            ranges.append(DiffRange(cur_s, cur_e))
        else:
            truncated = True

    common = min(a.size, b.size)
    for off in range(0, common, CHUNK):
        n = min(CHUNK, common - off)
        ca, cb = a.read(off, n), b.read(off, n)
        if ca == cb:
            continue
        for pos in _diff_positions(ca, cb, off):
            changed += 1
            if cur_s >= 0 and pos - cur_e <= gap:
                cur_e = pos + 1
            else:
                close()
                cur_s, cur_e = pos, pos + 1
    if a.size != b.size:
        close()
        cur_s = cur_e = -1
        count += 1
        changed += abs(a.size - b.size)
        r = DiffRange(common, max(a.size, b.size), a_only=a.size > b.size, b_only=b.size > a.size)
        if len(ranges) < MAX_RANGES:
            ranges.append(r)
        else:
            truncated = True
    else:
        close()
    return DiffResult(ranges, changed, count, truncated)


def _bytes_fmt(b: bytes) -> str:
    if len(b) > MAX_SHOWN_BYTES:
        return hx(b[:MAX_SHOWN_BYTES]) + f" …+{len(b) - MAX_SHOWN_BYTES}"
    return hx(b)


def range_lines(res: DiffResult, a: Src, b: Src, indent: str = "") -> list[str]:
    out = []
    for r in res.ranges:
        ln = r.end - r.start
        lo = max(0, r.start - CONTEXT)
        if r.a_only or r.b_only:
            src, tag = (a, "only in a") if r.a_only else (b, "only in b")
            out.append(f"{indent}0x{r.start:08x}-0x{r.end - 1:08x} {ln}B {tag}: "
                       f"{_bytes_fmt(src.read(r.start, min(ln, MAX_SHOWN_BYTES + 1)))}")
            continue
        end = min(a.size, b.size, r.end + CONTEXT)
        parts = []
        for tag, s in (("a", a), ("b", b)):
            pre = s.read(lo, r.start - lo)
            mid = s.read(r.start, ln)
            post = s.read(r.end, end - r.end)
            parts.append(f"{tag}: {hx(pre)} [{_bytes_fmt(mid)}] {hx(post)}".replace("  ", " "))
        out.append(f"{indent}0x{r.start:08x}-0x{r.end - 1:08x} {ln}B  " + "  ".join(parts))
    if res.truncated:
        out.append(f"{indent}… {res.range_count - len(res.ranges)} more ranges not listed")
    return out


def summary_of(res: DiffResult) -> str:
    return f"{res.range_count} ranges, {res.changed_bytes} bytes differ"


def ole_diff(pa: Path, pb: Path) -> list[str]:
    """Per-stream diff of two OLE files: added/removed/changed streams, then ranges."""
    oa, ob = olefile.OleFileIO(str(pa)), olefile.OleFileIO(str(pb))
    try:
        ma = {disp_path(p): p for p in oa.listdir(streams=True, storages=False)}
        mb = {disp_path(p): p for p in ob.listdir(streams=True, storages=False)}
        added, removed = sorted(set(mb) - set(ma)), sorted(set(ma) - set(mb))
        top = [f"added {n} {ob.get_size(mb[n])}B" for n in added] +               [f"removed {n} {oa.get_size(ma[n])}B" for n in removed]
        body: list[str] = []
        changed = 0
        for name in sorted(set(ma) & set(mb)):
            da, db = oa.openstream(ma[name]).read(), ob.openstream(mb[name]).read()
            if da == db:
                continue
            changed += 1
            a, b = BytesSrc(da), BytesSrc(db)
            res = diff_sources(a, b)
            body.append(f"changed {name} {a.size}B -> {b.size}B: {summary_of(res)}")
            body += range_lines(res, a, b, "  ")
        head = (f"ole diff {pa.name} vs {pb.name}: {changed} changed, {len(added)} added, "
                f"{len(removed)} removed of {len(set(ma) | set(mb))} streams")
        if not (changed or added or removed):
            return [head + ". All streams identical."]
        return [head] + top + body
    finally:
        oa.close()
        ob.close()


# -- record guessing ---------------------------------------------------------------------

@dataclass
class Guess:
    score: float
    lines: list[str]
    kind: str = ""
    span: tuple[int, int] = (0, 0)
    exact: bool = True
    recs: int = 0


_FILLER = re.compile(rb"(.)\1{15,}", re.S)   # runs of 16+ equal bytes: padding, not structure
_ZFILL = re.compile(rb"\x00{8,}|\xff{8,}")   # zero / ff padding
RUN_BLOCK = 16
MIN_RUN_DENSITY = 0.4


def _stride_scores(d: bytes) -> dict[int, float]:
    n = len(d)
    out = {}
    for s in range(2, min(MAX_STRIDE, n // 3) + 1):
        out[s] = _eq_map(d, s).count(0) / (n - s)       # XOR is zero where the bytes repeat
    return out


def _eq_map(d: bytes, s: int) -> bytes:
    """``d[i] ^ d[i + s]`` for every i, as bytes (0 where the byte repeats at +s)."""
    return (int.from_bytes(d[:-s], "big") ^ int.from_bytes(d[s:], "big")).to_bytes(len(d) - s, "big")


def _fmt_f(x: float) -> str:
    return f"{x:.6g}"


def _printable(b: int) -> bool:
    return 0x20 <= b < 0x7f


def _seq_note(vs: list[int]) -> str:
    """', +N per record' when the column is an arithmetic progression."""
    if len(vs) < 3:
        return ""
    step = vs[1] - vs[0]
    if step and all(vs[i + 1] - vs[i] == step for i in range(len(vs) - 1)):
        return f", {step:+d} per record"
    if all(vs[i + 1] > vs[i] for i in range(len(vs) - 1)):
        return ", ascending"
    return ""


def _int_col(chunks: list[bytes], w: int) -> tuple[str, list[int]] | None:
    """Best little/big-endian reading of an integer column: the one with the smaller maximum."""
    le = [int.from_bytes(c, "little") for c in chunks]
    be = [int.from_bytes(c, "big") for c in chunks]
    return ("", le) if max(le) <= max(be) else ("be", be)


def _column_fields(d: bytes, stride: int) -> list[str]:
    """Per-column summary of records of ``stride`` bytes: constants, text, ints, floats."""
    recs = min(len(d) // stride, 4096)
    if recs < 3:
        return []
    rows = [d[i * stride:(i + 1) * stride] for i in range(recs)]
    const = [len({r[j] for r in rows}) == 1 for j in range(stride)]
    prn = [all(_printable(r[j]) for r in rows) for j in range(stride)]
    out: list[str] = []
    j = 0
    while j < stride:
        if const[j]:
            end = j
            while end + 1 < stride and const[end + 1]:
                end += 1
            nxt = end + 1
            # a text field that starts with constant printable bytes stays one field
            if nxt < stride and prn[nxt] and all(prn[j:end + 1]) and end - j + 1 < 8 and nxt - j >= 0:
                t = nxt
                while t < stride and prn[t]:
                    t += 1
                if t - j >= 4:
                    out.append(f"+0x{j:02x} text {t - j} chars e.g. \"{rows[0][j:min(t, j + 16)].decode('ascii')}\"")
                    j = t
                    continue
            # keep the constant bytes that share an aligned word with a varied byte
            if nxt < stride:
                for w in (8, 4, 2):
                    ws = nxt - nxt % w
                    if j <= ws <= end and ws + w <= stride:
                        end = ws - 1
                        break
            if end >= j:
                vals = {rows[0][x] for x in range(j, end + 1)}
                cs = hx(rows[0][j:end + 1]) if end - j < 4 else f"{hx(rows[0][j:j + 4])} …"
                tag = "zero" if vals == {0} else f"const {cs}"
                out.append(f"+0x{j:02x}" + (f"..0x{end:02x}" if end > j else "") + f" {tag}")
                j = end + 1
                continue
        # text run (printable in every record)
        t = j
        while t < stride and prn[t]:
            t += 1
        if t - j >= 4:
            out.append(f"+0x{j:02x} text {t - j} chars e.g. \"{rows[0][j:min(t, j + 16)].decode('ascii')}\"")
            j = t
            continue
        got = None
        for w, kind in ((8, "f64"), (4, "u32"), (4, "f32"), (4, "u32be"), (2, "u16")):
            if j + w > stride or j % w:
                continue
            chunks = [r[j:j + w] for r in rows]
            if kind == "f64":
                vs = [struct.unpack("<d", c)[0] for c in chunks]
                ok = all(v == 0 or (math.isfinite(v) and 1e-9 < abs(v) < 1e12) for v in vs)
                if ok and len(set(vs)) > 1 and sum(1 for v in vs if v != 0) >= recs // 4:
                    got = (w, f"f64 {_fmt_f(min(vs))}..{_fmt_f(max(vs))} ({len(set(vs))} distinct)")
            elif kind == "f32":
                vs = [struct.unpack("<f", c)[0] for c in chunks]
                ok = all(v == 0 or (math.isfinite(v) and 1e-6 < abs(v) < 1e9) for v in vs)
                if ok and len(set(vs)) > 1 and sum(1 for v in vs if v != 0) >= recs // 4:
                    got = (w, f"f32 {_fmt_f(min(vs))}..{_fmt_f(max(vs))} ({len(set(vs))} distinct)")
            elif kind in ("u32", "u32be"):
                e = "be" if kind == "u32be" else ""
                vs = [int.from_bytes(c, "big" if e else "little") for c in chunks]
                if max(vs) < 1 << 24 and len(set(vs)) > 1:
                    got = (w, f"u32{e} {min(vs)}..{max(vs)} ({len(set(vs))} distinct{_seq_note(vs)})")
            else:
                e, vs = _int_col(chunks, w)
                if len(set(vs)) > 1:
                    got = (w, f"u16{e} {min(vs)}..{max(vs)} ({len(set(vs))} distinct{_seq_note(vs)})")
            if got:
                break
        if got:
            out.append(f"+0x{j:02x} {got[1]}")
            j += got[0]
        else:
            out.append(f"+0x{j:02x} byte {len({r[j] for r in rows})} distinct")
            j += 1
    # collapse consecutive plain byte columns
    merged: list[str] = []
    for ln in out:
        if merged and ln.split(" ", 1)[1].startswith("byte") and merged[-1].split(" ", 1)[1].startswith("byte"):
            first = merged[-1].split(" ", 1)[0].split("..")[0]
            merged[-1] = f"{first}..{ln.split(' ', 1)[0][1:]} bytes (varied)"
            continue
        merged.append(ln)
    return merged


def _best_run(m: bytes, thr: float) -> tuple[float, int, int]:
    """Best run of matches in a 0/1 byte string: +1-thr per match, -thr per miss. (gain, start, end)."""
    gm, gx = 1.0 - thr, -thr
    best, bs, be, cur, cs = 0.0, 0, 0, 0.0, 0
    for i, v in enumerate(m):
        if v == 2:          # padding byte: neutral
            continue
        if cur <= 0:
            cur, cs = 0.0, i
        cur += gm if v else gx
        if cur > best:
            best, bs, be = cur, cs, i + 1
    return best, bs, be


def _stride_region(d: bytes, s: int) -> tuple[int, int]:
    """Where records of stride ``s`` run inside ``d``: (first record start, end of last record)."""
    w = d[:256 * 1024]
    m = bytes(map(operator.eq, w, w[s:]))
    # inside long zero / ff runs a match is padding: it counts neither for nor against the stride
    pad = bytearray(len(m))
    for mt in _ZFILL.finditer(w):
        pad[mt.start():min(mt.end(), len(m))] = b"\x01" * (min(mt.end(), len(m)) - mt.start())
    pi = int.from_bytes(bytes(pad), "big")
    mi = int.from_bytes(m, "big")
    neutral = mi & pi
    mm = ((mi & (neutral ^ int.from_bytes(b"\x01" * len(m), "big"))) | (neutral << 1)).to_bytes(len(m), "big")
    _, a, b = _best_run(mm, 0.35)
    if b <= a:
        return 0, len(d)
    # the padding-blind run is the core; extend it by up to one record where plain matches continue
    cur = best = 0.0
    ext = 0
    for k in range(1, min(s, a) + 1):
        cur += 0.65 if m[a - k] else -0.35
        if cur > best:
            best, ext = cur, k
    a -= ext
    cur = best = 0.0
    ext = 0
    for k in range(0, min(s, len(m) - b)):
        cur += 0.65 if m[b + k] else -0.35
        if cur > best:
            best, ext = cur, k + 1
    return a, min(b + ext + s, len(d))


def _stride_guess(d: bytes, s: int, score: float, ratio: float, base: float, org: int) -> Guess:
    a, e = _stride_region(d, s)
    if a <= 8 and len(d) - e < s:
        a, e = 0, len(d)
    recs, rest = divmod(e - a, s)
    if a == 0 and e == len(d):
        head = (f"fixed stride {s}: {recs} records, {rest} bytes left over; "
                f"{ratio * 100:.0f}% of bytes repeat at +{s} (typical {base * 100:.0f}%)")
    else:
        head = (f"fixed stride {s}: {recs} records from 0x{org + a:x} to 0x{org + e:x}; "
                f"{ratio * 100:.0f}% of bytes repeat at +{s} (typical {base * 100:.0f}%)")
    return Guess(score, [head] + ["  " + f for f in _column_fields(d[a:e], s)[:14]], "stride", (a, e), True, (e - a) // s)


def _fundamentals(strong: list[int]) -> list[int]:
    chosen: list[int] = []
    for s in sorted(strong):
        if not any(s % c == 0 for c in chosen):
            chosen.append(s)
    return chosen


_EQ01 = bytes([1] + [0] * 255)      # equal -> 1


def _block_sums(m: bytes) -> bytes:
    """Number of ones in each full RUN_BLOCK of the 0/1 bytes ``m`` (big-integer adds, no carries)."""
    if len(m) < RUN_BLOCK:
        return b""
    t = int.from_bytes(m, "big")
    sh = 1
    while sh < RUN_BLOCK:       # sums of 2, 4, 8, 16 neighbours
        t += t >> (8 * sh)
        sh *= 2
    return t.to_bytes(len(m), "big")[RUN_BLOCK - 1::RUN_BLOCK]


def _local_stride_guesses(d: bytes, org: int) -> list[Guess]:
    """Strides that hold only inside part of the window (header or tail around the records)."""
    sample = d[:STRIDE_SAMPLE]
    n = len(sample)
    if n < 24:
        return []
    fill = bytearray(n)
    for mt in _FILLER.finditer(sample):
        fill[mt.start():mt.end()] = b"\x01" * (mt.end() - mt.start())
    keep = int.from_bytes(bytes(1 - x for x in fill), "big")
    gains: dict[int, tuple[float, int, int]] = {}
    ratios = []
    cands = {}
    for s in range(2, min(MAX_STRIDE, n // 3) + 1):
        m = _eq_map(sample, s).translate(_EQ01)
        k = int.from_bytes(m, "big") & (keep >> (8 * s))
        m = k.to_bytes(len(m), "big")
        ratios.append(m.count(1) / len(m))
        cands[s] = m
    if not ratios:
        return []
    base = sorted(ratios)[len(ratios) // 2]
    thr = max(0.30, base + 0.15)
    up = bytes(max(0, math.ceil(c - thr * RUN_BLOCK + 1e-9)) for c in range(256))
    for s, m in cands.items():
        sums = _block_sums(m)
        tail = len(m) % RUN_BLOCK
        # no run can gain more than the positive blocks add up to: most strides stop here
        if sum(sums.translate(up)) + (m.count(1, len(m) - tail) if tail else 0) < 24:
            continue
        cur = best = 0.0
        cs = bs = be = 0
        for bi, c in enumerate(sums):
            c -= thr * RUN_BLOCK
            if cur <= 0:
                cur, cs = 0.0, bi
            cur += c
            if cur > best:
                best, bs, be = cur, cs, bi + 1
        if tail:
            bi = len(sums)
            c = m.count(1, bi * RUN_BLOCK) - thr * tail
            if cur <= 0:
                cur, cs = 0.0, bi
            cur += c
            if cur > best:
                best, bs, be = cur, cs, bi + 1
        run = (be - bs) * RUN_BLOCK
        if run >= 3 * s and best >= 24:
            dens = m.count(1, bs * RUN_BLOCK, be * RUN_BLOCK) / run
            if dens >= MIN_RUN_DENSITY:
                gains[s] = (best, bs * RUN_BLOCK, be * RUN_BLOCK)
    if not gains:
        return []
    peaks = [s for s, (g, _, _) in gains.items()
             if g >= gains.get(s - 1, (0,))[0] and g >= gains.get(s + 1, (0,))[0]]
    if not peaks:
        return []
    top = max(gains[s][0] for s in peaks)
    out = []
    for s in _fundamentals([s for s in peaks if gains[s][0] >= 0.9 * top])[:2]:
        g, a, b = gains[s]
        dens = cands[s].count(1, a, b) / max(b - a, 1)
        out.append(_stride_guess(d, s, 0.1 + min(dens, 1.0) * 0.4, dens, base, org))
    return out


def _strides(d: bytes, org: int = 0) -> list[Guess]:
    sample = d[:STRIDE_SAMPLE]
    if len(sample) < 24:
        return []
    sc = _stride_scores(sample)
    if not sc:
        return []
    vals = sorted(sc.values())
    base = vals[len(vals) // 2]
    if base > 0.95:
        return _local_stride_guesses(d, org)
    peaks = [s for s, v in sc.items()
             if v - base >= 0.15 and v >= sc.get(s - 1, 0) and v >= sc.get(s + 1, 0)]
    if not peaks:
        return _local_stride_guesses(d, org)
    top = max(sc[s] for s in peaks)
    strong = [s for s in peaks if sc[s] >= 0.9 * top]
    return [_stride_guess(d, s, sc[s] - base, sc[s], base, org) for s in _fundamentals(strong)[:3]]


# -- length-prefixed chains --------------------------------------------------------------

_CHAIN_STARTS = tuple(range(0, 33)) + (48, 64, 96, 100, 128, 256, 512)
_STRUCTS = {(w, big): struct.Struct((">" if big else "<") + c)
            for w, c in ((2, "H"), (4, "I"), (8, "Q")) for big in (False, True)}
HOP_BUDGET = 6_000_000
NULL_SAMPLE = 16 * 1024
MIN_CHAIN_BITS = 26
CHAIN_WINDOW = 256 * 1024
CALIBRATION_WINDOW = 128 * 1024


def _chain_configs():
    """(k, w, big, hx, tr, unit, align, incl): length at +k of w bytes, hx header bytes after it,
    tr trailer bytes; step = k+w+hx+tr + len*unit (incl: step = len*unit), rounded up to align."""
    for w in (2, 4, 8):
        for big in (False, True):
            for k in (0, 1, 2, 3, 4, 6, 8):
                for hxx in (0, 2, 4, 8):
                    for tr in (0, 2, 4):
                        for unit in (1, 2):
                            yield (k, w, big, hxx, tr, unit, 1, False)
                yield (k, w, big, 0, 0, 1, 1, True)
                for al in (2, 4):
                    yield (k, w, big, 0, 0, 1, al, False)


class _Chain:
    __slots__ = ("cfg", "start", "recs", "end", "bits", "steps", "why")


def _walk(d: bytes, n: int, start: int, cfg: tuple, budget: list[int], keep: list[int] | None = None,
          null: list[int] | None = None):
    k, w, big, hxx, tr, unit, al, incl = cfg
    st = _STRUCTS[(w, big)]
    a = 0 if incl else k + w + hxx + tr
    lo = k + w
    pos, recs, bits, zero = start, 0, 0.0, 0
    steps: set[int] = set()
    why = "end"
    while pos + lo <= n:
        ln = st.unpack_from(d, pos + k)[0]
        step = a + ln * unit
        if al > 1:
            step = (step + al - 1) // al * al
        if step < lo:
            why = "bad"
            break
        if ln == 0:
            zero += 1
            if zero > recs // 4 + 1:
                why = "bad"
                break
        if pos + step > n:
            why = "over"
            break
        if null is None:
            bits += 8 * w - 1 - math.log2(step)
        else:   # chance that a random field value would have fit into what is left of the data
            bits -= math.log2(max(bisect_right(null, n - pos), 1) / len(null))
        if len(steps) < 3:
            steps.add(step)
        if keep is not None:
            keep.append(pos)
        recs += 1
        pos += step
        budget[0] -= 1
        if pos == n:
            break
    return recs, pos, bits, len(steps), why


def _prep(cfg: tuple) -> tuple:
    k, w, big, hxx, tr, unit, al, incl = cfg
    return k, _STRUCTS[(w, big)], 0 if incl else k + w + hxx + tr, k + w, unit, al


def _quick(d: bytes, n: int, start: int, prep: tuple) -> int:
    """Records (0, 1, or 2 for 'two or more') that ``_walk`` would count at ``start``; most starts fail in
    the first two records, and this tells so without the bookkeeping of a full walk."""
    k, st, a, lo, unit, al = prep
    pos, zero = start, 0
    for rec in (0, 1):
        if pos + lo > n:
            return rec
        ln = st.unpack_from(d, pos + k)[0]
        step = a + ln * unit
        if al > 1:
            step = (step + al - 1) // al * al
        if step < lo or pos + step > n:
            return rec
        if ln == 0:
            zero += 1
            if zero > 1:
                return rec
        pos += step
        if pos == n:
            return rec + 1
    return 2


def _varint(d: bytes, p: int, n: int) -> tuple[int, int] | None:
    v = sh = 0
    for i in range(5):
        if p + i >= n:
            return None
        b = d[p + i]
        v |= (b & 0x7f) << sh
        sh += 7
        if b < 0x80:
            return v, i + 1
    return None


def _walk_varint(d: bytes, n: int, start: int, k: int, keep: list[int] | None = None):
    pos, recs, zero = start, 0, 0
    steps: set[int] = set()
    while pos + k + 1 <= n:
        r = _varint(d, pos + k, n)
        if r is None:
            break
        ln, vl = r
        step = k + vl + ln
        if ln == 0:
            zero += 1
            if zero > recs // 4 + 1:
                break
        if pos + step > n:
            break
        if len(steps) < 3:
            steps.add(step)
        if keep is not None:
            keep.append(pos)
        recs += 1
        pos += step
        if pos == n:
            break
    return recs, pos, len(steps)


def _tag_note(d: bytes, starts: list[int], cfg: tuple) -> str:
    k, w, big, hxx, tr, unit, al, incl = cfg
    if k in (1, 2, 4):
        off, tb = 0, k
    elif k == 0 and hxx in (2, 4):
        off, tb = w, hxx
    else:
        return ""
    c: Counter = Counter()
    for p in starts[:4000]:
        raw = d[p + off:p + off + tb]
        if len(raw) == tb:
            c[raw] += 1
    if len(c) > 12 or not c:
        return ""
    def show(raw: bytes) -> str:
        if all(_printable(x) for x in raw):
            return raw.decode("ascii")
        return f"0x{int.from_bytes(raw, 'big' if big and tb > 1 and k == 0 else 'little'):0{tb * 2}x}"
    items = ", ".join(f"{show(r)}x{n}" if n > 1 else show(r) for r, n in c.most_common(6))
    return f"; tag at +{off} ({tb}B): {items}"


def _cfg_text(cfg: tuple) -> str:
    k, w, big, hxx, tr, unit, al, incl = cfg
    fld = f"u{w * 8}{'be' if big else 'le'}"
    if incl:
        step = "len" + (f"*{unit}" if unit != 1 else "")
    else:
        step = f"{k + w + hxx + tr} + len" + (f"*{unit}" if unit != 1 else "")
    return f"{fld} at +{k}, step = {step}" + (f", padded to {al}" if al > 1 else "")


def _block_shuffle(x: bytes, blk: int = 16) -> bytes:
    """Same bytes in a different block order: keeps local number statistics, destroys chains."""
    rnd = random.Random(7)
    blocks = [x[i:i + blk] for i in range(0, len(x), blk)]
    rnd.shuffle(blocks)
    return b"".join(blocks)


def _tag_bits(d: bytes, starts: list[int], cfg: tuple) -> float:
    """Evidence from a text tag (RIFF/PNG/IFF style) in front of or behind every length field."""
    k, w, big, hxx, tr, unit, al, incl = cfg
    if k in (3, 4):
        off, tb = 0, k
    elif k == 0 and hxx in (4, 8):
        off, tb = w, hxx
    else:
        return 0.0
    for p in starts[:8]:
        raw = d[p + off:p + off + tb]
        if len(raw) < tb or not all(chr(x).isalnum() or x == 0x20 for x in raw):
            return 0.0
    return 2.0 * tb * min(len(starts), 6)


def _chain_evidence(d: bytes, n: int, last_nz: int, full: bool, cfg: tuple, start: int, pos: int,
                    recs: int, bits: float, why: str) -> tuple[bool, bool, bool, float]:
    """(exact, pad, cut, evidence bits) of a finished chain walk."""
    pad = pos >= last_nz
    tl = n - pos
    # a lone pad byte, or a trailer that repeats the bytes before the first record (container magic)
    near = (tl <= 1 and cfg[6] > 1) or (4 <= tl <= 16 and start >= tl and d[pos:] == d[start - tl:start])
    exact = full and (pad or near)
    cut = (not full) and (why == "over" or pos == n)
    gain = 0.0
    if exact and pad:
        gain = math.log2(max((pos - start) / max(recs, 1), 2))
    return exact, pad, cut, bits + gain


def _all_ints(b: bytes, w: int, big: bool) -> list[int]:
    """Sorted w-byte integers at every position of ``b``."""
    out: list[int] = []
    code = {2: "H", 4: "I", 8: "Q"}[w]
    for ph in range(w):
        m = (len(b) - ph) // w
        if m > 0:
            out += struct.unpack_from(f"{'>' if big else '<'}{m}{code}", b, ph)
    out.sort()
    return out


def _chains(d: bytes, window_full: bool, org: int = 0, entropy: float = 0.0) -> list[Guess]:
    n = len(d)
    if n < 16:
        return []
    found: dict[tuple, tuple] = {}
    budget = [HOP_BUDGET]
    last_nz = len(d.rstrip(b"\0"))
    probe = d[:NULL_SAMPLE]
    nulls = {(w, big): _all_ints(probe, w, big) for w in (2, 4, 8) for big in (False, True)}
    cfgs = list(_chain_configs())

    # null: the same data with its blocks shuffled still has the same small numbers, but no chains
    cn = min(n, CALIBRATION_WINDOW)
    sd = _block_shuffle(d[:cn])
    sfull = window_full and cn == n
    slast = len(sd.rstrip(b"\0"))
    cal = 0.0
    cbudget = [HOP_BUDGET // 2]
    for cfg in cfgs:
        prep = _prep(cfg)
        for start in _CHAIN_STARTS:
            if start + cfg[0] + cfg[1] > cn or cbudget[0] <= 0:
                continue
            q = _quick(sd, cn, start, prep)
            if q < 2:
                cbudget[0] -= q
                continue
            recs, pos, bits, ds, why = _walk(sd, cn, start, cfg, cbudget, None, nulls[(cfg[1], cfg[2])])
            if recs >= 2:
                ex, _p, cut, ev = _chain_evidence(sd, cn, slast, sfull, cfg, start, pos, recs, bits, why)
                if ex or cut or recs >= 16:
                    cal = max(cal, ev)
    need = max(MIN_CHAIN_BITS, cal + 6)

    def consider(cfg, start, recs, pos, bits, ds, why):
        exact, pad, cut, ev = _chain_evidence(d, n, last_nz, window_full, cfg, start, pos, recs, bits, why)
        if recs < 2 or ev + 24 < need or bits < 8 or (recs >= 3 and ds < 3):
            return
        if not (exact or cut) and (recs < 16 or bits < 100):
            return
        keep: list[int] = []
        _walk(d, n, start, cfg, [10 ** 9], keep)
        ev += _tag_bits(d, keep, cfg)
        if ev < need:
            return
        mine = set(keep)
        # a real chain breaks when the start moves; generic small-number tables do not
        for sh in range(1, 17):
            alt: list[int] = []
            r2 = _walk(d, n, start + sh, cfg, [10 ** 9], alt)
            if r2[0] >= max(3, recs // 2) and sum(1 for x in alt if x in mine) * 2 < len(alt):
                return
        avg = (pos - start) / recs
        tail = ("chain ends exactly at 0x%x" % (org + n) if exact and pad else
                "chain ends %d bytes before 0x%x" % (n - pos, org + n) if exact else
                "chain runs through the window" if cut else
                "chain stops at 0x%x (next length does not fit)" % (org + pos))
        line = f"length-prefixed {_cfg_text(cfg)}: {recs} records from 0x{org + start:x}, avg {avg:.0f} bytes, {tail}"
        line += _tag_note(d, keep, cfg)
        score = 0.6 + min(ev, 240) / 240 * 0.6 + (0.2 if exact else 0.0) + min(recs, 200) / 4000
        score -= start / 1e7
        key = (start + cfg[0], cfg[1], pos, recs)
        if key not in found or found[key][0] < score:
            found[key] = (score, Guess(score, [line], "chain", (start, pos), exact, recs),
                          (exact, pos, recs, {p + cfg[0] + cfg[1] for p in keep[:400]}, mine, start))

    for cfg in cfgs:
        w = cfg[1]
        prep = _prep(cfg)
        covered: set[int] = set()
        for start in _CHAIN_STARTS:
            if start + cfg[0] + w > n or start in covered:
                continue
            if budget[0] <= 0:
                break
            q = _quick(d, n, start, prep)
            if q < 2:
                budget[0] -= q
                continue
            keep: list[int] = []
            recs, pos, bits, ds, why = _walk(d, n, start, cfg, budget, keep, nulls[(w, cfg[2])])
            if recs >= 2:
                covered.update(keep)
            consider(cfg, start, recs, pos, bits, ds, why)
    # 1-byte and varint lengths: no information beyond the chain ending exactly
    if entropy <= 7.0 and window_full:
        for k, vint in ((0, False), (0, True), (1, False), (1, True)):
            for start in (0, 1, 2, 4, 8, 16):
                if vint:
                    recs, pos, ds = _walk_varint(d, n, start, k)
                    name = f"varint at +{k}, step = {k} + varint size + len"
                else:
                    recs, pos, ds = _walk_u8(d, n, start, k)
                    name = f"u8 at +{k}, step = {k + 1} + len"
                avg = (pos - start) / max(recs, 1)
                if pos != n or recs < 12 or ds < 3 or avg < 24 or math.log2(avg) + recs / 40 < 7:
                    continue
                line = (f"length-prefixed {name}: {recs} records from 0x{org + start:x}, avg {avg:.0f} bytes, "
                        f"chain ends exactly at 0x{org + n:x}")
                score = 0.4 + math.log2(avg) / 40 + min(recs, 200) / 4000
                key = (start, pos, recs)
                if key not in found:
                    found[key] = (score, Guess(score, [line], "chain", (start, pos), True, recs),
                                  (True, pos, recs, set(), set(), start))
    kept: list[tuple[Guess, tuple]] = []
    for _, g, meta in sorted(found.values(), key=lambda t: -t[0]):
        dup = False
        for i2, (g2, m2) in enumerate(kept):
            same_end = meta[0] and m2[0] and meta[1] == m2[1] and min(meta[2], m2[2]) * 2 >= max(meta[2], m2[2])
            share = len(meta[3] & m2[3]) * 2 >= min(len(meta[3]), len(m2[3])) if meta[3] and m2[3] else False
            same_recs = len(meta[4] & m2[4]) * 2 >= min(len(meta[4]), len(m2[4])) if meta[4] and m2[4] else False
            if same_end or share or same_recs:
                dup = True
                if meta[5] < m2[5] and meta[0] >= m2[0] and meta[2] >= m2[2]:      # the same chain read from an earlier start: keep the earlier
                    kept[i2] = (g, meta)
                break
        if not dup:
            kept.append((g, meta))
    return [g for g, _ in kept[:2]]


def _walk_u8(d: bytes, n: int, start: int, k: int):
    pos, recs, zero = start, 0, 0
    steps: set[int] = set()
    while pos + k + 1 <= n:
        ln = d[pos + k]
        step = k + 1 + ln
        if ln == 0:
            zero += 1
            if zero > recs // 4 + 1:
                break
        if pos + step > n:
            break
        if len(steps) < 3:
            steps.add(step)
        recs += 1
        pos += step
        if pos == n:
            break
    return recs, pos, len(steps)


_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _strings(d: bytes, base: int) -> list[str]:
    asc = [(m.start(), m.end() - m.start()) for m in _ASCII.finditer(d)]
    u16 = [(m.start(), (m.end() - m.start()) // 2) for m in _U16.finditer(d)]
    if not asc and not u16:
        return []
    out = [f"strings: {len(asc)} ascii runs, {len(u16)} utf-16le runs"]
    allp = sorted([(o, ln, "a") for o, ln in asc] + [(o, ln, "w") for o, ln in u16])
    if len(allp) >= 3:
        deltas = Counter(allp[i + 1][0] - allp[i][0] for i in range(len(allp) - 1))
        dv, dc = deltas.most_common(1)[0]
        if dc >= 3 and dc * 3 >= len(allp):
            out.append(f"  strings recur at spacing {dv} ({dc} of {len(allp) - 1} gaps)")
    pre = Counter()
    for o, ln, k in allp:
        chars = ln
        byte_len = ln * (2 if k == "w" else 1)
        for w, fmt in ((1, "<B"), (2, "<H"), (4, "<I")):
            if o >= w and struct.unpack_from(fmt, d, o - w)[0] in (chars, chars + 1, byte_len):
                pre[w] += 1
    if pre:
        w, c = pre.most_common(1)[0]
        if c * 2 >= len(allp) and c >= 3:
            out.append(f"  u{w * 8} length prefix right before {c} of {len(allp)} runs")
    for o, ln, k in sorted(allp, key=lambda x: -x[1])[:6]:
        txt = d[o:o + ln * (2 if k == "w" else 1)]
        s = txt.decode("utf-16le" if k == "w" else "ascii")
        s = s if len(s) <= 40 else s[:39] + "…"
        out.append(f"  0x{base + o:x} {'utf16' if k == 'w' else 'ascii'} {ln} chars \"{s}\"")
    return out


def _extra_guesses(d: bytes, offset: int, full: bool, entropy: float) -> list[Guess]:
    found = []
    for f in (recdetect.pgp_packets(d, offset, full), recdetect.preg_records(d, offset),
              recdetect.class_file(d, offset)):
        if f:
            found.append(f)
    if not found:
        found = [f for f in (recdetect.delimited_text(d, offset),
                             recdetect.offset_tables(d, offset, _column_fields, full)) if f]
    return [Guess(f.score, f.lines, f.kind, f.span, True, f.recs) for f in found]


def record_guess(src: Src, offset: int = 0) -> list[str]:
    if offset < 0 or offset >= src.size:
        return [f"error bad_args: offset 0x{offset:x} is outside the data ({src.size} bytes)."]
    d = src.read(offset, GUESS_WINDOW)
    full = offset + len(d) >= src.size
    head = f"record_guess region 0x{offset:x}-0x{offset + len(d):x} ({len(d)} bytes{'' if full else ', window cut'})"
    if len(d) < 16:
        return [head, "too small to guess a layout."]
    entropy = _entropy(d[:65536])
    strides = _strides(d, offset)
    chains = _chains(d[:CHAIN_WINDOW], full and len(d) <= CHAIN_WINDOW, offset, entropy)
    # a table of small numbers also chains by accident; a stride over the same span explains it better
    chains = [c for c in chains if c.recs < 8 or not any(
        min(c.span[1], t.span[1]) - max(c.span[0], t.span[0]) >= 0.8 * (c.span[1] - c.span[0]) for t in strides)]
    guesses = strides + chains
    extra = _extra_guesses(d, offset, full, entropy)
    stream = recdetect.sample_stream(d) if not extra else None
    if any(g.kind in ("pgp", "preg", "class") for g in extra):
        guesses = []                      # an exact packet / record chain explains the bytes
    elif stream:                          # a waveform has no records; keep only exact chains (RIFF)
        guesses = [g for g in guesses if g.kind == "chain" and g.exact]
    else:
        spans = [g.span for g in extra if g.kind in ("text", "table")]
        guesses = [g for g in guesses if not any(
            g.kind == "stride" and g.recs < 20 and min(g.span[1], b) - max(g.span[0], a) >= 0.5 * (g.span[1] - g.span[0])
            for a, b in spans)]
    big = [g.span for g in guesses if g.kind == "stride" and g.recs >= 20]
    extra = [g for g in extra if not (g.kind == "table" and any(
        min(g.span[1], b) - max(g.span[0], a) >= 0.9 * (g.span[1] - g.span[0]) for a, b in big))]
    guesses = guesses + extra
    guesses.sort(key=lambda g: -g.score)
    out = [head]
    for g in guesses[:4]:
        out += g.lines
    if stream:
        out.append(stream)
    elif not guesses:
        out.append("no fixed stride or length-prefixed chain found.")
    if entropy <= 7.5 and not stream and not any(g.kind in ("pgp", "preg", "class") for g in extra):
        out += _strings(d, offset)
    out.append(f"entropy {entropy:.2f} bits/byte" + (" (looks compressed or encrypted)" if entropy > 7.5 else ""))
    return out


def _entropy(d: bytes) -> float:
    if not d:
        return 0.0
    n = len(d)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(d).values()))


def stream_src(data: bytes) -> BytesSrc:
    return BytesSrc(data)

