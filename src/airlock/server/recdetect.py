"""Extra record detectors for record_guess (DESIGN 6): OpenPGP packets, delimited text, registry
policy files, small offset/length tables and sample streams.

Pure functions over bytes. Each returns ``Found`` objects (or None / []) that fileformat wraps into
its Guess type. Precision first: a detector answers only when random data would hardly fit.
"""

from __future__ import annotations

import csv
import io
import math
import operator
import re
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Callable


@dataclass
class Found:
    score: float
    lines: list[str]
    kind: str
    span: tuple[int, int]
    recs: int


# -- OpenPGP packets ---------------------------------------------------------------------

PGP_TAGS = {1: "pkesk", 2: "sig", 3: "skesk", 4: "onepass", 5: "seckey", 6: "pubkey", 7: "secsubkey",
            8: "compressed", 9: "symenc", 10: "marker", 11: "literal", 12: "trust", 13: "uid",
            14: "subkey", 17: "attr", 18: "seipd", 19: "mdc", 20: "aead", 21: "padding"}
_PGP_VERSIONS = {1: (3, 6), 2: (3, 4, 5, 6), 3: (4, 5, 6), 4: (3, 6), 5: (2, 3, 4, 5, 6), 6: (2, 3, 4, 5, 6),
                 7: (2, 3, 4, 5, 6), 14: (2, 3, 4, 5, 6), 18: (1, 2), 20: (1,)}


def _pgp_packet(d: bytes, p: int, n: int):
    """(tag, header kind, end) of the packet at ``p``; None when it is not a plausible packet."""
    b = d[p]
    if not b & 0x80:
        return None
    if b & 0x40:
        tag, kind = b & 0x3f, "new"
        q = p + 1
        first = True
        end = None
        first_body = None
        while True:
            if q >= n:
                return None
            o = d[q]
            if o < 192:
                ln, q = o, q + 1
                width = 1
            elif o < 224:
                if q + 1 >= n:
                    return None
                ln, q = ((o - 192) << 8) + d[q + 1] + 192, q + 2
                width = 2
            elif o == 255:
                if q + 4 >= n:
                    return None
                ln, q = int.from_bytes(d[q + 1:q + 5], "big"), q + 5
                width = 5
            else:       # partial body length: more chunks follow
                ln, q = 1 << (o & 0x1f), q + 1
                width = 1
                if first_body is None:
                    first_body = q
                if tag not in (8, 9, 11, 18, 20):
                    return None
                if q + ln > n:
                    return None
                q += ln
                first = False
                kind = "new partial"
                continue
            if first:
                kind = f"new {width}B"
            if first_body is None:
                first_body = q
            end = q + ln
            break
        start_body = first_body
    else:
        tag = (b >> 2) & 15
        lt = b & 3
        kind = f"old {(1, 2, 4, 0)[lt]}B" if lt < 3 else "old open"
        if lt == 0:
            if p + 1 >= n:
                return None
            ln, start_body = d[p + 1], p + 2
        elif lt == 1:
            if p + 2 >= n:
                return None
            ln, start_body = int.from_bytes(d[p + 1:p + 3], "big"), p + 3
        elif lt == 2:
            if p + 4 >= n:
                return None
            ln, start_body = int.from_bytes(d[p + 1:p + 5], "big"), p + 5
        else:
            ln, start_body = n - p - 1, p + 1
        end = start_body + ln
    if tag not in PGP_TAGS or end > n or end <= start_body and tag not in (10, 12, 13, 17, 19):
        return None
    if start_body < n:
        v = d[start_body]
        ok = _PGP_VERSIONS.get(tag)
        if ok and v not in ok:
            return None
        if tag == 11 and v not in b"tbulm1":
            return None
        if tag == 8 and v > 3:
            return None
        if tag == 10 and d[start_body:end] != b"PGP":
            return None
        if tag == 19 and end - start_body != 20:
            return None
    strict = _pgp_body(tag, d[start_body:min(end, start_body + 4096)], end - start_body, kind)
    if strict is False:
        return None
    return tag, kind, end, strict


_PK_ALGOS = (1, 2, 3, 16, 17, 18, 19, 22)
_HASH_ALGOS = (1, 2, 3, 8, 9, 10, 11)
_SIG_TYPES = (0, 1, 2, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1f, 0x20, 0x28, 0x30, 0x40, 0x50, 0x51)


def _mpis(b: bytes, p: int, count: int) -> int | None:
    for _ in range(count):
        if p + 2 > len(b):
            return None
        bits = int.from_bytes(b[p:p + 2], "big")
        if bits == 0:
            return None
        p += 2 + (bits + 7) // 8
        if p > len(b):
            return None
    return p


def _pgp_body(tag: int, b: bytes, size: int, kind: str):
    """True when the packet body parses as its tag says, False when it cannot, None when the tag has
    no structure to check (user ids are checked as text)."""
    if "partial" in kind:
        return None
    if not b:
        return None if tag in (12, 17, 19, 10) else False
    if tag in (5, 6, 7, 14):
        v = b[0]
        if v in (4, 5, 6) and len(b) >= 6:
            algo, p = b[5], 6
        elif v in (2, 3) and len(b) >= 8:
            algo, p = b[7], 8
        else:
            return False
        if algo not in _PK_ALGOS:
            return False
        if algo in (1, 2, 3):
            e = _mpis(b, p, 2)
        elif algo == 17:
            e = _mpis(b, p, 4)
        elif algo == 16:
            e = _mpis(b, p, 3)
        else:               # curve OID, then one MPI (ECDH adds KDF parameters)
            if p >= len(b) or not 3 <= b[p] <= 12:
                return False
            e = _mpis(b, p + 1 + b[p], 1)
        if e is None or (tag in (6, 14) and algo not in (18, 19, 22) and e != size):
            return False
        return True
    if tag == 2:
        v = b[0]
        if v == 3:
            return len(b) > 19 and b[1] == 5 and b[2] in _SIG_TYPES and b[15] in _PK_ALGOS and b[16] in _HASH_ALGOS
        if v not in (4, 5, 6) or len(b) < 8:
            return False
        if b[1] not in _SIG_TYPES or b[2] not in _PK_ALGOS or b[3] not in _HASH_ALGOS:
            return False
        hl = int.from_bytes(b[4:6], "big")
        if 6 + hl + 2 > size:
            return False
        ul = int.from_bytes(b[6 + hl:8 + hl], "big") if 8 + hl <= len(b) else 0
        return 8 + hl + ul + 2 <= size
    if tag == 1:
        return b[0] == 3 and size > 10 and b[9] in _PK_ALGOS
    if tag == 3:
        return b[0] == 4 and len(b) > 2 and b[1] <= 13 and b[2] in (0, 1, 3)
    if tag == 4:
        return b[0] == 3 and size == 13 and b[1] in _SIG_TYPES and b[2] in _HASH_ALGOS and b[3] in _PK_ALGOS
    if tag in (18, 20):
        return b[0] in (1, 2)
    if tag == 13:
        try:
            t = b.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return t.isprintable() and len(t) >= 2
    if tag == 11:
        return (len(b) > 6 and 6 + b[1] <= size and b[0] in b"btu"
                and all(32 <= x < 127 or x >= 128 for x in b[2:2 + b[1]]))
    if tag == 10:
        return True
    return None


def pgp_packets(d: bytes, org: int, full: bool) -> Found | None:
    n = len(d)
    if n < 16:
        return None
    best = None
    for start in range(0, 9):
        pos, recs, strict = start, 0, 0
        tags: Counter = Counter()
        kinds: Counter = Counter()
        while pos < n:
            r = _pgp_packet(d, pos, n)
            if r is None:
                break
            strict += bool(r[3])
            tags[r[0]] += 1
            kinds[r[1]] += 1
            recs += 1
            pos = r[2]
        tail = n - pos
        if pos < n and d[pos:].strip(b"\0") == b"":
            tail = 0
        exact = pos == n or tail == 0
        if recs == 0 or not (exact or (not full and recs >= 4)):
            continue
        if (start and recs < 3) or not strict or (recs == 1 and n < 64):
            continue
        key = (recs, -start)
        if best is None or key > best[0]:
            best = (key, start, pos, recs, tags, kinds, exact)
    if best is None:
        return None
    _k, start, pos, recs, tags, kinds, exact = best
    tg = ", ".join(f"{PGP_TAGS[t]}x{c}" if c > 1 else PGP_TAGS[t] for t, c in sorted(tags.items()))
    kd = ", ".join(f"{k} x{c}" for k, c in sorted(kinds.items()))
    tail = f"chain ends exactly at 0x{org + n:x}" if exact else "chain runs through the window"
    line = f"openpgp packets: {recs} records from 0x{org + start:x}, {tail}"
    return Found(1.4 + min(recs, 20) / 100 + (0.1 if recs >= 2 else 0.0),
                 [line, f"  tags: {tg}", f"  headers (length width): {kd}"], "pgp", (start, pos), recs)


# -- registry policy files (PReg) ---------------------------------------------------------

def _u16z(d: bytes, p: int, n: int):
    """UTF-16LE string up to a NUL character at ``p``: (text, next position) or None."""
    q = p
    while q + 1 < n:
        if d[q] == 0 and d[q + 1] == 0:
            try:
                return d[p:q].decode("utf-16le"), q + 2
            except UnicodeDecodeError:
                return None
        q += 2
        if q - p > 1024:
            return None
    return None


_REG_TYPES = {0: "none", 1: "sz", 2: "expand_sz", 3: "binary", 4: "dword", 5: "dword_be", 6: "link",
              7: "multi_sz", 11: "qword"}


def preg_records(d: bytes, org: int) -> Found | None:
    """``[key;value;type;size;data]`` records, UTF-16LE, as in Registry.pol."""
    n = len(d)
    for start in (8, 0, 2, 4, 6, 10, 12, 16):
        if start + 2 > n or d[start:start + 2] != b"[\x00":
            continue
        pos, recs = start, 0
        types: Counter = Counter()
        keys: Counter = Counter()
        while pos + 2 <= n and d[pos:pos + 2] == b"[\x00":
            k = _u16z(d, pos + 2, n)
            if k is None or d[k[1]:k[1] + 2] != b";\x00":
                break
            v = _u16z(d, k[1] + 2, n)
            if v is None or d[v[1]:v[1] + 2] != b";\x00":
                break
            q = v[1] + 2
            if q + 4 > n or d[q + 4:q + 6] != b";\x00":
                break
            typ = int.from_bytes(d[q:q + 4], "little")
            q += 6
            if q + 4 > n or d[q + 4:q + 6] != b";\x00":
                break
            size = int.from_bytes(d[q:q + 4], "little")
            q += 6
            if q + size + 2 > n or d[q + size:q + size + 2] != b"]\x00":
                break
            types[_REG_TYPES.get(typ, f"0x{typ:x}")] += 1
            keys[k[0]] += 1
            recs += 1
            pos = q + size + 2
        if recs >= 2 and pos >= n - 4:
            tp = ", ".join(f"{t}x{c}" for t, c in types.most_common(5))
            line = (f"bracketed records [key;value;type;size;data] (utf-16le): {recs} records from "
                    f"0x{org + start:x}, chain ends at 0x{org + pos:x}; types {tp}")
            return Found(1.5, [line, f"  {len(keys)} distinct keys, first \"{next(iter(keys))[:48]}\""],
                         "preg", (start, pos), recs)
    return None


# -- delimited text -----------------------------------------------------------------------

_TEXT_SPAN = re.compile(rb"[\t\r\n\x20-\x7e\x80-\xff]{48,}")
_TEXT16_SPAN = re.compile(rb"(?:[\t\r\n\x20-\x7e]\x00){32,}")
_DELIMS = (",", ";", "\t", "|", ":")
_DNAME = {",": "comma", ";": "semicolon", "\t": "tab", "|": "pipe", ":": "colon"}
_INT = re.compile(r"[+-]?\d+$")
_NUM = re.compile(r"[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}([T ][\d:.]+Z?)?$")


def _col_type(vals: list[str]) -> str:
    vs = [v.strip() for v in vals]
    ne = [v for v in vs if v]
    if not ne:
        return "empty"
    pct = f" {100 * len(ne) // len(vs)}% filled" if len(ne) < len(vs) * 0.9 else ""
    if all(_INT.match(v) for v in ne):
        iv = [int(v) for v in ne]
        return f"int {min(iv)}..{max(iv)}{pct}"
    if all(_NUM.match(v) for v in ne):
        fv = [float(v) for v in ne]
        return f"number {min(fv):.6g}..{max(fv):.6g}{pct}"
    if all(_DATE.match(v) for v in ne):
        return f"date {min(ne)}..{max(ne)}{pct}"
    if {v.lower() for v in ne} <= {"true", "false", "yes", "no", "0", "1"}:
        return f"bool{pct}"
    lens = [len(v) for v in ne]
    dist = len(set(ne))
    return f"text {min(lens)}..{max(lens)} chars, {dist} distinct{pct}"


def _rows_of(text: str, dl: str):
    try:
        return [r for r in csv.reader(io.StringIO(text, newline=""), delimiter=dl, strict=False) if r]
    except csv.Error:
        return None


def _delimited(text: str, org: int, a: int, b: int, enc: str) -> Found | None:
    if text.count("\n") + text.count("\r") < 3:
        return None
    eol = "CRLF" if "\r\n" in text else "LF" if "\n" in text else "CR"
    best = None
    for dl in _DELIMS:
        if text.count(dl) < 6:
            continue
        rows = _rows_of(text, dl)
        if rows is None or len(rows) < 4:
            continue
        # the first and last row may be cut by the span edge
        inner = rows[1:-1] if len(rows) > 5 else rows
        counts = Counter(len(r) for r in inner)
        m, c = counts.most_common(1)[0]
        if m < (3 if dl == ":" else 2) or c < 0.9 * len(inner) or c < 3:
            continue
        cells = [x for r in inner[:200] for x in r]
        if sorted(len(x) for x in cells)[len(cells) // 2] > 64:
            continue
        # prose with a stable comma count per line is rare; require that fields differ between rows
        if len({tuple(r) for r in inner}) < max(2, len(inner) // 2):
            continue
        key = (m, c)
        if best is None or key > best[0]:
            best = (key, dl, rows, m, c)
    if best is None:
        return None
    _k, dl, rows, m, c = best
    good = [r for r in rows if len(r) == m]
    header = None
    if len(good) >= 3:
        h, body = good[0], good[1:]
        if rows[0] is good[0] or rows[0] == h:
            hn = sum(1 for x in h if x.strip() and not _NUM.match(x.strip()))
            numcols = sum(1 for j in range(m) if _col_type([r[j] for r in body[:200]]).startswith(("int", "number")))
            if hn == m and len(set(h)) == m and (numcols or all(len(x) < 40 for x in h)):
                header = h
    body = good[1:] if header else good
    line = (f"delimited text ({enc}): {len(body)} rows x {m} fields, separator {_DNAME[dl]}, {eol} line ends, "
            f"from 0x{org + a:x} to 0x{org + b:x}; {c} of {len(rows) - (2 if len(rows) > 5 else 0)} rows have {m} fields")
    out = [line]
    if header:
        out.append("  header row: " + dl.join(x[:20] for x in header[:12]) + (" …" if m > 12 else ""))
    for j in range(min(m, 12)):
        name = f" {header[j][:24]}" if header else ""
        out.append(f"  field {j + 1}{name}: {_col_type([r[j] for r in body[:2000]])}")
    if m > 12:
        out.append(f"  … {m - 12} more fields")
    quoted = sum(1 for r in body[:200] for x in r if '"' in x)
    if quoted:
        out.append("  quoted fields present (\"\" escapes)")
    return Found(1.3 + min(len(body), 100) / 400, out, "text", (a, b), len(body))


def delimited_text(d: bytes, org: int) -> Found | None:
    """Line records with a fixed separator, in a text file or inside a binary blob."""
    cands: list[tuple[int, int, str, str]] = []
    for mt in sorted(_TEXT_SPAN.finditer(d), key=lambda m: m.start() - m.end())[:3]:
        s = mt.group()
        if sum(1 for x in s if x < 0x80) < 0.95 * len(s):
            continue
        try:
            t = s.decode("utf-8")
        except UnicodeDecodeError:
            t = s.decode("latin-1")
        cands.append((mt.start(), mt.end(), t, "ascii/utf-8"))
    for mt in sorted(_TEXT16_SPAN.finditer(d), key=lambda m: m.start() - m.end())[:2]:
        cands.append((mt.start(), mt.end(), mt.group().decode("utf-16le"), "utf-16le"))
    best = None
    for a, b, t, enc in cands:
        f = _delimited(t, org, a, b, enc)
        if f and (best is None or f.recs > best.recs):
            best = f
    return best


# -- small offset/length tables ------------------------------------------------------------

TABLE_START_MAX = 128


def offset_tables(d: bytes, org: int, columns: Callable[[bytes, int], list[str]]) -> Found | None:
    """A directory of (offset, length) pairs that point into the data: ICO entries, TrueType and WOFF
    table directories, PE sections. Three entries are enough because random fields hardly fit."""
    n = len(d)
    if n < 64:
        return None
    lim = min(n, 4096 + 128 + 80)
    le = [struct.unpack_from("<I", d, p)[0] if p + 4 <= n else 0 for p in range(lim)]
    be = [struct.unpack_from(">I", d, p)[0] if p + 4 <= n else 0 for p in range(lim)]
    def pair_ok(arr: list[int], p: int, q: int) -> bool:
        return 24 <= arr[p] < n and 0 < arr[q] <= n - arr[p]
    okp = {}
    for big, arr in ((False, le), (True, be)):
        for order in (0, 1):
            okp[(big, order)] = [p + 8 <= lim and (pair_ok(arr, p, p + 4) if order == 0 else pair_ok(arr, p + 4, p))
                                 for p in range(lim)]
    best = None
    for start in range(0, min(n, TABLE_START_MAX)):
        for S in range(8, 65):
            if start + 3 * S > n or start + 3 * S + 8 > lim:
                break
            for a in range(0, S - 7):
                for arr, big in ((le, False), (be, True)):
                    for order, (oa, la) in enumerate(((a, a + 4), (a + 4, a))):
                        if not okp[(big, order)][start + a]:
                            continue
                        off0, ln0 = arr[start + oa], arr[start + la]
                        if not (start + 3 * S <= off0 < n and 0 < ln0 <= n - off0):
                            continue
                        offs, lens = [], []
                        k = 0
                        while start + (k + 1) * S <= n:
                            p = start + k * S
                            if p + max(oa, la) + 4 > lim:
                                break
                            off, ln = arr[p + oa], arr[p + la]
                            if not (off >= start + 3 * S and 0 < ln <= n - off):
                                break
                            offs.append(off)
                            lens.append(ln)
                            k += 1
                        while k >= 3:       # the last entries may already be the data behind the table
                            rng = sorted(zip(offs[:k], lens[:k]))
                            if len(set(lens[:k])) >= 2 and rng[0][0] >= start + k * S and rng[-1][0] + rng[-1][1] >= n // 4 and not any(
                                    rng[i][0] + rng[i][1] > rng[i + 1][0] for i in range(k - 1)):
                                break
                            k -= 1
                        if k < 3:
                            continue
                        offs, lens = offs[:k], lens[:k]
                        # directly behind the table, or four entries with unaligned values (a table of
                        # small shifted numbers, as in the dBase field list, has neither)
                        if not (min(offs) - (start + k * S) < 16
                                or (k >= 4 and any(x % 256 for x in offs) and any(x % 256 for x in lens))):
                            continue
                        cover = k * S
                        cand = (k, -S, -start, cover, start, S, oa, la, big, offs, lens)
                        if best is None or cand[:3] > best[:3]:
                            best = cand
    if best is None:
        return None
    k, _s, _t, _cv, start, S, oa, la, big, offs, lens = best
    contig = sum(1 for i in range(k - 1) if offs[i] + lens[i] == offs[i + 1])
    asc = all(offs[i] < offs[i + 1] for i in range(k - 1))
    after = "right after the table" if min(offs) == start + k * S else f"0x{org + min(offs):x}"
    e = "be" if big else "le"
    line = (f"offset/length table: {k} entries x {S} bytes from 0x{org + start:x}; offset u32{e} at +{oa}, "
            f"length u32{e} at +{la}; {'ascending' if asc else 'unordered'} non-overlapping ranges, lowest points {after}"
            + (f", {contig} of {k - 1} contiguous" if contig else ""))
    out = [line]
    cols = columns(d[start:start + k * S], S)
    out += ["  " + c for c in cols[:12]]
    return Found(1.35 + min(k, 20) / 200, out, "table", (start, start + k * S), k)


# -- sample streams ------------------------------------------------------------------------

STREAM_BLOCK = 1024


def _block_stats(b: bytes) -> tuple[float, float]:
    """(roughness, standard deviation) of a block: mean |step| over lags 1 and 2 (the smaller; lag 2 is
    the other channel of a stereo stream) divided by the deviation. About 1.1 for noise and byte
    structures, below 0.7 for a waveform."""
    n = len(b)
    mean = sum(b) / n
    sd = math.sqrt(sum((x - mean) ** 2 for x in b) / n)
    if sd == 0:
        return 0.0, 0.0
    rough = min(sum(map(abs, map(operator.sub, b[lag:], b))) / (n - lag) for lag in (1, 2)) / sd
    return rough, sd


def sample_stream(d: bytes) -> str | None:
    """Text of the 'sample stream, no records' verdict when the data is a smooth 8-bit waveform."""
    n = len(d)
    if n < 4 * STREAM_BLOCK:
        return None
    if sum(32 <= x < 127 for x in d[:8192]) > 0.85 * len(d[:8192]):
        return None                 # text and digits are smooth too
    blocks = [d[i:i + STREAM_BLOCK] for i in range(0, n - STREAM_BLOCK + 1, STREAM_BLOCK)]
    step = max(1, len(blocks) // 48)
    sel = blocks[::step]
    for variant in ("unsigned", "signed"):
        ok = wave = 0
        for b in sel:
            v = b if variant == "unsigned" else bytes((x + 128) & 255 for x in b)
            r, sd = _block_stats(v)
            mean = sum(v) / len(v)
            if abs(mean - 128) > 40:
                continue
            if sd < 1.5:
                ok += 1             # digital silence near mid-scale
            elif sd >= 2 and r <= 0.7 and (variant == "unsigned" or max(Counter(v).values()) <= 0.2 * len(v)) and len({(v[i + 1] - v[i]) for i in range(len(v) - 1)}) >= 6:
                ok += 1
                wave += 1
        if ok >= 0.75 * len(sel) and wave >= 0.4 * len(sel):
            lo, hi = min(d), max(d)
            return (f"sample stream: 8-bit PCM-like waveform ({lo}..{hi}, {variant} centre, neighbouring samples "
                    f"smooth), no records; channel count and rate come from the container header")
    return None
