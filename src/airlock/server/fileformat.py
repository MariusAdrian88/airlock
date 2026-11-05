"""Raw file inspection without Ghidra: OLE streams, hexdump, diff, record guessing (DESIGN 6).

Pure functions over byte sources; the tool module (tools/fileformat.py) resolves paths and pages
the output. Everything here is memory-bounded: files are read in chunks or capped windows.
"""

from __future__ import annotations

import math
import operator
import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

import olefile

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
        return f"error not_ole: {path.name} is not an OLE compound file ({type(e).__name__}). Use hexdump."
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
        return f"error not_ole: {path.name} is not an OLE compound file. Omit stream, or use hexdump."
    try:
        parts = find_stream(ole, name)
        if parts is None:
            return (f"error not_found: no stream '{name}' in {path.name}. "
                    "Call ole_streams without stream to list them.")
        if ole.get_size(parts) > cap:
            return f"error too_big: stream {disp_path(parts)} is over {cap >> 20} MiB. Use another approach."
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


def _stride_scores(d: bytes) -> dict[int, float]:
    n = len(d)
    out = {}
    for s in range(2, min(MAX_STRIDE, n // 3) + 1):
        eq = sum(map(operator.eq, d, d[s:]))
        out[s] = eq / (n - s)
    return out


def _fmt_f(x: float) -> str:
    return f"{x:.6g}"


def _column_fields(d: bytes, stride: int) -> list[str]:
    """Per-column summary of records of ``stride`` bytes: constants, ints, floats."""
    recs = min(len(d) // stride, 4096)
    if recs < 3:
        return []
    rows = [d[i * stride:(i + 1) * stride] for i in range(recs)]
    out: list[str] = []
    j = 0
    while j < stride:
        col = [r[j] for r in rows]
        if len(set(col)) == 1:
            end = j
            while end + 1 < stride and len({r[end + 1] for r in rows}) == 1:
                end += 1
            vals = {rows[0][x] for x in range(j, end + 1)}
            const = hx(rows[0][j:end + 1]) if end - j < 4 else f"{hx(rows[0][j:j + 4])} …"
            tag = "zero" if vals == {0} else f"const {const}"
            out.append(f"+0x{j:02x}" + (f"..0x{end:02x}" if end > j else "") + f" {tag}")
            j = end + 1
            continue
        got = None
        for w, kind in ((8, "f64"), (4, "f32"), (4, "u32"), (2, "u16")):
            if j + w > stride:
                continue
            if kind == "f64" and j % 8:
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
            elif kind == "u32":
                vs = [int.from_bytes(c, "little") for c in chunks]
                if max(vs) < 1 << 24:
                    got = (w, f"u32 {min(vs)}..{max(vs)} ({len(set(vs))} distinct)")
            else:
                vs = [int.from_bytes(c, "little") for c in chunks]
                if len(set(vs)) > 1:
                    got = (w, f"u16 {min(vs)}..{max(vs)} ({len(set(vs))} distinct)")
            if got:
                break
        if got:
            out.append(f"+0x{j:02x} {got[1]}")
            j += got[0]
        else:
            cnt = Counter(col)
            out.append(f"+0x{j:02x} byte {len(cnt)} distinct")
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


def _strides(d: bytes) -> list[Guess]:
    sample = d[:STRIDE_SAMPLE]
    if len(sample) < 24:
        return []
    sc = _stride_scores(sample)
    if not sc:
        return []
    vals = sorted(sc.values())
    base = vals[len(vals) // 2]
    if base > 0.95:
        return []
    peaks = [s for s, v in sc.items()
             if v - base >= 0.15 and v >= sc.get(s - 1, 0) and v >= sc.get(s + 1, 0)]
    if not peaks:
        return []
    top = max(sc[s] for s in peaks)
    strong = sorted(s for s in peaks if sc[s] >= 0.9 * top)
    chosen: list[int] = []
    for s in strong:
        if not any(s % c == 0 for c in chosen):
            chosen.append(s)
    out = []
    for s in chosen[:3]:
        recs, rest = divmod(len(d), s)
        head = (f"fixed stride {s}: {recs} records, {rest} bytes left over; "
                f"{sc[s] * 100:.0f}% of bytes repeat at +{s} (typical {base * 100:.0f}%)")
        out.append(Guess(sc[s] - base, [head] + ["  " + f for f in _column_fields(d, s)[:14]]))
    return out


def _chains(d: bytes, window_full: bool) -> list[Guess]:
    n = len(d)
    out = []
    for w, fmt in ((1, "<B"), (2, "<H"), (4, "<I")):
        for incl in (False, True):
            for start in (0, 2, 4, 8, 16):
                if start + w > n:
                    continue
                pos, recs, zero = start, 0, 0
                while pos + w <= n:
                    ln = struct.unpack_from(fmt, d, pos)[0]
                    step = ln if incl else w + ln
                    if step < w:
                        break
                    if ln == 0:
                        zero += 1
                        if zero > recs // 4 + 1:
                            break
                    nxt = pos + step
                    if nxt > n:
                        break
                    recs += 1
                    pos = nxt
                    if pos == n:
                        break
                if recs < 4:
                    continue
                exact = pos == n and window_full
                cut = pos == n or (not window_full and pos + w > n - 8192)
                if not (exact or (not window_full and cut)):
                    continue
                avg = (pos - start) / recs
                bits = math.log2(max(avg, 2)) - 6   # chance 1/avg per random try, ~60 tries
                if exact and bits < 0 and w == 1 and recs < 64:
                    continue
                lines = [f"length-prefixed u{w * 8}le{' incl. prefix' if incl else ''}"
                         f" from 0x{start:x}: {recs} records, avg {avg:.0f} bytes, "
                         f"{'chain ends exactly at ' + hex(n) if exact else 'chain runs through the window'}"]
                out.append(Guess(0.5 + bits / 10 + (0.2 if exact else 0) + min(recs, 200) / 2000, lines))
    out.sort(key=lambda g: -g.score)
    seen, kept = set(), []
    for g in out:
        key = g.lines[0].split(":")[1]
        if key in seen:
            continue
        seen.add(key)
        kept.append(g)
    return kept[:2]


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


def record_guess(src: Src, offset: int = 0) -> list[str]:
    if offset < 0 or offset >= src.size:
        return [f"error bad_args: offset 0x{offset:x} is outside the data ({src.size} bytes). Use 0 to {max(src.size - 1, 0)}."]
    d = src.read(offset, GUESS_WINDOW)
    full = offset + len(d) >= src.size
    head = f"record_guess region 0x{offset:x}-0x{offset + len(d):x} ({len(d)} bytes{'' if full else ', window cut'})"
    if len(d) < 16:
        return [head, "too small to guess a layout."]
    guesses = _strides(d) + _chains(d, full)
    guesses.sort(key=lambda g: -g.score)
    out = [head]
    for g in guesses[:4]:
        out += g.lines
    if not guesses:
        out.append("no fixed stride or length-prefixed chain found.")
    entropy = _entropy(d[:65536])
    if entropy <= 7.5:
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

