"""Extra record detectors for record_guess (DESIGN 6): OpenPGP packets, delimited text, registry
policy files, small offset/length tables, Java class files and sample streams.

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
TABLE_SCAN = 4096 + 128 + 80


def _fields(d: bytes, n: int, lim: int, w: int, big: bool) -> list[int]:
    """The ``w``-byte integer at every position below ``lim`` (0 where it would run past the data)."""
    arr = [0] * lim
    code = {2: "H", 4: "I", 8: "Q"}[w]
    for ph in range(min(w, lim)):
        m = min((lim - 1 - ph) // w + 1, (n - ph) // w)
        if m > 0:
            arr[ph:ph + (m - 1) * w + 1:w] = struct.unpack_from(f"{'>' if big else '<'}{m}{code}", d, ph)
    return arr


def _ok_positions(arr: list[int], lim: int, w: int, n: int, floor: int, order: int) -> list[int]:
    """Positions ``p`` where two adjacent fields (``order`` 0: offset first) form a range inside the data."""
    out = []
    for p in range(lim - 2 * w + 1):
        x, y = (arr[p], arr[p + w]) if order == 0 else (arr[p + w], arr[p])
        if floor <= x < n and 0 < y <= n - x:
            out.append(p)
    return out


def _table_chains(oks: dict, w: int, lim: int, n: int):
    """(p, S, big, order, offs, lens): positions ``p``, ``p + S``, ``p + 2S`` ... that all hold a plausible
    range (three or more), where the ranges reach into the last quarter of the data."""
    out = []
    for (big, order), (ok, arr) in oks.items():
        oset = set(ok)
        oa, la = (0, w) if order == 0 else (w, 0)
        for p in ok:
            for S in range(2 * w, 65):
                if p + S not in oset or p + 2 * S not in oset:
                    continue
                if w == 2:      # 16-bit fields are short of evidence: the first three ranges must tile
                    r3 = sorted((arr[p + j * S + oa], arr[p + j * S + la]) for j in range(3))
                    if r3[0][0] + r3[0][1] != r3[1][0] or r3[1][0] + r3[1][1] != r3[2][0]:
                        continue
                offs, lens = [], []
                q = p
                while q in oset:
                    offs.append(arr[q + oa])
                    lens.append(arr[q + la])
                    q += S
                if max(o + ln for o, ln in zip(offs, lens)) >= n // 4:
                    out.append((p, S, big, order, offs, lens))
    return out


def _walk_table(offs, lens, start, S, n, lim, w):
    k = 0
    while k < len(offs) and start + (k + 1) * S <= n and offs[k] >= start + 3 * S:
        k += 1
    return offs[:k], lens[:k]


def _scan_tables(d: bytes, n: int, lim: int, w: int):
    """Best table of 3 or more entries with ``w``-byte offset and length fields, as a tuple whose first
    items (entries, -stride, -start, ...) rank it; ties go to the earliest start, field and order."""
    arrs = {big: _fields(d, n, lim, w, big) for big in (False, True)}
    oks = {(big, order): (_ok_positions(arrs[big], lim, w, n, 6 * w, order), arrs[big])
           for big in (False, True) for order in (0, 1)}
    best = None
    for p, S, big, order, coffs, clens in _table_chains(oks, w, lim, n):
        for start in range(max(0, p - (S - 2 * w)), min(p, TABLE_START_MAX - 1) + 1):
            if start + 3 * S > n or start + 3 * S + 2 * w > lim:
                continue
            a = p - start
            oa, la = (a, a + w) if order == 0 else (a + w, a)
            offs, lens = _walk_table(coffs, clens, start, S, n, lim, w)
            k = len(offs)
            while k >= 3:       # the last entries may already be the data behind the table
                rng = sorted(zip(offs[:k], lens[:k]))
                if (len(set(lens[:k])) >= 2 and rng[0][0] >= start + k * S and rng[-1][0] + rng[-1][1] >= n // 4
                        and not any(rng[i][0] + rng[i][1] > rng[i + 1][0] for i in range(k - 1))
                        and (w != 2 or all(rng[i][0] + rng[i][1] == rng[i + 1][0] for i in range(k - 1)))):
                    break
                k -= 1
            if k < 3:
                continue
            offs, lens = offs[:k], lens[:k]
            # directly behind the table, or four entries with unaligned values (a table of small shifted
            # numbers, as in the dBase field list, has neither); 16-bit fields must tile exactly
            behind = min(offs) - (start + k * S)
            if w == 2:
                if not (behind == 0 or max(o + ln for o, ln in zip(offs, lens)) == n):
                    continue
            elif not (behind < 16 or (k >= 4 and any(x % 256 for x in offs) and any(x % 256 for x in lens))):
                continue
            cand = (k, -S, -start, -a, -big, -order, start, S, oa, la, big, offs, lens, w)
            if best is None or cand[:6] > best[:6]:
                best = cand
    if best is None:
        return None
    return best[0], best[1], best[2], *best[6:]


def _tile_tables(d: bytes, n: int, lim: int, w: int):
    """One or two entries whose ranges tile the rest of the data exactly: the lowest offset right behind
    the table, the ranges back to back, the last one ending at the end of the data."""
    best = None
    for big in (False, True):
        arr = _fields(d, n, lim, w, big)
        for order in (0, 1):
            ok = _ok_positions(arr, lim, w, n, 2 * w, order)
            oset = set(ok)
            oa, la = (0, w) if order == 0 else (w, 0)
            for p in ok:
                x0, y0 = arr[p + oa], arr[p + la]
                if p < TABLE_START_MAX and x0 >= p + 2 * w and x0 + y0 == n:
                    cand = (1, 0, -p, p, 2 * w, oa, la, big, [x0], [y0], w)
                    if best is None or cand[:3] > best[:3]:
                        best = cand
                for S in range(2 * w, 65):
                    if p + S not in oset:
                        continue
                    x1, y1 = arr[p + S + oa], arr[p + S + la]
                    lo, hi = sorted(((x0, y0), (x1, y1)))
                    for start in range(max(0, p - (S - 2 * w)), min(p, TABLE_START_MAX - 1) + 1):
                        if lo[0] == start + 2 * S and lo[0] + lo[1] == hi[0] and hi[0] + hi[1] == n:
                            cand = (2, -S, -start, start, S, p - start + oa, p - start + la, big, [x0, x1], [y0, y1], w)
                            if best is None or cand[:3] > best[:3]:
                                best = cand
    return best


def offset_tables(d: bytes, org: int, columns: Callable[[bytes, int], list[str]], full: bool = True) -> Found | None:
    """A directory of (offset, length) pairs that point into the data: ICO entries, TrueType and WOFF
    table directories, PE sections. Three entries are enough because random fields hardly fit (16-bit
    fields must tile exactly); one or two entries only when their ranges tile the rest of the data."""
    n = len(d)
    if n < 64:
        return None
    lim = min(n, TABLE_SCAN)
    best = None
    for w in (4, 8, 2):
        if w == 2 and n // 4 > 2 * 65535:       # 16-bit ranges cannot reach into the last quarter
            continue
        best = _scan_tables(d, n, lim, w)
        if best:
            break
    if best is None and full:
        for w in (4, 8):
            best = _tile_tables(d, n, lim, w)
            if best:
                break
    if best is None:
        return None
    k, _s, _t, start, S, oa, la, big, offs, lens, w = best
    ty = f"u{8 * w}{'be' if big else 'le'}"
    if k == 1:
        line = (f"offset/length pair: {ty} offset at +{oa} and length at +{la} from 0x{org + start:x}; the range "
                f"0x{org + offs[0]:x}..0x{org + n:x} covers the rest of the data exactly")
        return Found(1.35 + 1 / 200, [line], "table", (start, start + 2 * w), 1)
    contig = sum(1 for i in range(k - 1) if offs[i] + lens[i] == offs[i + 1])
    asc = all(offs[i] < offs[i + 1] for i in range(k - 1))
    after = "right after the table" if min(offs) == start + k * S else f"0x{org + min(offs):x}"
    tiled = ", the ranges tile the data exactly" if max(o + ln for o, ln in zip(offs, lens)) == n and (k < 3 or w == 2) else ""
    line = (f"offset/length table: {k} entries x {S} bytes from 0x{org + start:x}; offset {ty} at +{oa}, "
            f"length {ty} at +{la}; {'ascending' if asc else 'unordered'} non-overlapping ranges, lowest points {after}"
            + (f", {contig} of {k - 1} contiguous" if contig else "") + tiled)
    out = [line]
    cols = columns(d[start:start + k * S], S)
    out += ["  " + c for c in cols[:12]]
    return Found(1.35 + min(k, 20) / 200, out, "table", (start, start + k * S), k)


# -- Java class files ----------------------------------------------------------------------

_CP_NAMES = {1: "Utf8", 3: "Integer", 4: "Float", 5: "Long", 6: "Double", 7: "Class", 8: "String", 9: "Fieldref",
             10: "Methodref", 11: "InterfaceMethodref", 12: "NameAndType", 15: "MethodHandle", 16: "MethodType",
             17: "Dynamic", 18: "InvokeDynamic", 19: "Module", 20: "Package"}
_CP_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
_CLASS_MAGIC = b"\xca\xfe\xba\xbe"


def _java_version(major: int) -> str:
    return {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4"}.get(major, str(major - 44))


def _class_at(d: bytes, org: int, p: int) -> Found | None:
    n = len(d)
    if p + 10 > n:
        return None
    u16 = lambda q: int.from_bytes(d[q:q + 2], "big")
    major, count = u16(p + 6), u16(p + 8)
    if not 45 <= major <= 80 or count < 5:
        return None
    q, idx = p + 10, 1
    tags: Counter = Counter()
    kind: dict[int, int] = {}
    ref: dict[int, int] = {}
    utf: dict[int, tuple[int, int]] = {}
    while idx < count:
        if q >= n:
            return None
        t = d[q]
        if t == 1:
            if q + 3 > n:
                return None
            ln = u16(q + 1)
            utf[idx] = (q + 3, ln)
            q += 3 + ln
        elif t in _CP_FIXED:
            if t == 7:
                ref[idx] = u16(q + 1) if q + 3 <= n else 0
            q += 1 + _CP_FIXED[t]
        else:
            return None
        if q > n:
            return None
        kind[idx] = t
        tags[_CP_NAMES[t]] += 1
        idx += 2 if t in (5, 6) else 1
    if idx != count or q + 8 > n:
        return None
    flags, this, sup, icount = u16(q), u16(q + 2), u16(q + 4), u16(q + 6)

    def name_of(ci: int) -> str | None:
        u = utf.get(ref.get(ci, -1))
        return d[u[0]:u[0] + u[1]].decode("utf-8", "replace") if u else None

    tname = name_of(this)
    if tname is None or not re.fullmatch(r"[\w$/.\-<>]{1,200}", tname) or (sup and kind.get(sup) != 7):
        return None
    pool_end = q
    q += 8 + 2 * icount
    members = []
    for _ in range(2):          # fields, then methods
        if q + 2 > n:
            q = -1
            break
        cnt = u16(q)
        q += 2
        for _ in range(cnt):
            if q + 8 > n:
                q = -1
                break
            ac = u16(q + 6)
            q += 8
            for _ in range(ac):
                if q + 6 > n or u16(q) not in utf:
                    q = -1
                    break
                q += 6 + int.from_bytes(d[q + 2:q + 6], "big")
            if q < 0 or q > n:
                q = -1
                break
        if q < 0:
            break
        members.append(cnt)
    end = None
    if q > 0 and q + 2 <= n and len(members) == 2:
        ac = u16(q)
        q += 2
        for _ in range(ac):
            if q + 6 > n or u16(q) not in utf:
                q = -1
                break
            q += 6 + int.from_bytes(d[q + 2:q + 6], "big")
        if 0 < q <= n:
            end = q
    sname = name_of(sup) if sup else None
    tg = ", ".join(f"{t}x{c}" for t, c in tags.most_common(6))
    line = (f"java class file: version {major}.{u16(p + 4)} (Java {_java_version(major)}), constant pool of {count - 1} slots "
            f"({sum(tags.values())} entries) from 0x{org + p + 10:x} to 0x{org + pool_end:x}")
    out = [line, f"  class {tname}" + (f", super {sname}" if sname else "") + f", access 0x{flags:x}, {icount} interfaces"]
    if len(members) == 2:
        tail = f"; the class ends exactly at 0x{org + end:x}" + (" (end of data)" if end == n else "") if end else ""
        out.append(f"  {members[0]} fields, {members[1]} methods{tail}")
    out.append(f"  pool entries: {tg}")
    return Found(1.5, out, "class", (p, end or pool_end), sum(tags.values()))


def class_file(d: bytes, org: int) -> Found | None:
    """A Java class file: the magic, then the constant pool (tag-dependent entry sizes, long and double
    take two slots), checked by the this-class entry and the field/method tables behind it."""
    p = d.find(_CLASS_MAGIC)
    for _ in range(4):
        if p < 0:
            return None
        f = _class_at(d, org, p)
        if f:
            return f
        p = d.find(_CLASS_MAGIC, p + 1)
    return None


# -- sample streams ------------------------------------------------------------------------

STREAM_BLOCK = 1024
NOISY_ROUGH = 0.88          # a noisy waveform still has neighbours that correlate (rho), noise has none
NOISY_RHO = 0.4


def _block_stats(b, parity: bool = False) -> tuple[float, float]:
    """(roughness, standard deviation) of a block: mean |step| over lags 1 and 2 (the smaller; lag 2 is
    the other channel of a stereo stream; the larger of the even and odd steps) divided by the deviation. About 1.1 for noise and byte
    structures, below 0.7 for a waveform."""
    n = len(b)
    mean = sum(b) / n
    sd = math.sqrt(sum((x - mean) ** 2 for x in b) / n)
    if sd == 0:
        return 0.0, 0.0
    # with ``parity`` every second step is measured apart: the low bytes of a 16-bit stream are noise between smooth
    # high bytes, which must not pass as a smooth 8-bit stream
    best = 1e9
    for lag in (1, 2):
        steps = list(map(abs, map(operator.sub, b[lag:], b)))
        m = sum(steps) / len(steps)
        if parity:
            m = max(sum(steps[0::2]) / len(steps[0::2]), sum(steps[1::2]) / len(steps[1::2]))
        best = min(best, m)
    return best / sd, sd


def _rho(b) -> float:
    """Correlation of neighbouring samples (the larger of lag 1 and 2)."""
    n = len(b)
    mean = sum(b) / n
    c = [x - mean for x in b]
    var = sum(x * x for x in c) / n
    return max(sum(map(operator.mul, c[lag:], c)) / ((n - lag) * var) for lag in (1, 2)) if var else 0.0


def _smooth(b, r: float, sd: float, noisy: bool) -> bool:
    if r <= 0.7:
        return True
    return noisy and r <= NOISY_ROUGH and sd >= 2 and _rho(b) >= NOISY_RHO


def _is_text(b: bytes) -> bool:
    """Valid UTF-8 (a cut last character is fine) that is not mostly control bytes or zeros."""
    try:
        b.decode("utf-8")
    except UnicodeDecodeError as e:
        if e.start < len(b) - 4:
            return False
    return sum(x >= 32 for x in b) > 0.8 * len(b)


def _stream8(d: bytes, sel: list[bytes], noisy: bool) -> str | None:
    for variant in ("unsigned", "signed"):
        ok = wave = fail = 0
        for b in sel:
            if fail > 0.25 * len(sel):
                break               # 75% of the blocks can no longer be waveform
            v = b if variant == "unsigned" else bytes((x + 128) & 255 for x in b)
            mean = sum(v) / len(v)
            if abs(mean - 128) > 40:
                fail += 1
                continue
            r, sd = _block_stats(v, True)
            if sd < 1.5:
                ok += 1             # digital silence near mid-scale
            elif (sd >= 2 and _smooth(v, r, sd, noisy) and (variant == "unsigned" or max(Counter(v).values()) <= 0.2 * len(v))
                  and len({(v[i + 1] - v[i]) for i in range(len(v) - 1)}) >= 6):
                ok += 1
                wave += 1
            else:
                fail += 1
        if ok >= 0.75 * len(sel) and wave >= 0.4 * len(sel):
            lo, hi = min(d), max(d)
            return (f"sample stream: 8-bit PCM-like waveform ({lo}..{hi}, {variant} centre, neighbouring samples "
                    f"smooth), no records; channel count and rate come from the container header")
    return None


def _stream16(d: bytes, n: int, noisy: bool) -> str | None:
    """16-bit little-endian PCM, mono or interleaved stereo; the sample phase is tried both ways."""
    step = max(1, ((n - 1) // STREAM_BLOCK) // 48)
    for phase in (0, 1):
        pos = range(phase, n - STREAM_BLOCK + 1, STREAM_BLOCK * step)
        if len(pos) < 4:
            return None
        ok = wave = stereo = fail = 0
        lo, hi = 32767, -32768
        for i in pos:
            if fail > 0.25 * len(pos):
                break               # 75% of the blocks can no longer be waveform
            v = struct.unpack_from("<%dh" % (STREAM_BLOCK // 2), d, i)
            mean = sum(v) / len(v)
            r, sd = _block_stats(v)
            if sd < 1.5:
                if abs(mean) < 4:
                    ok += 1
                else:
                    fail += 1
            elif (abs(mean) <= 0.5 * sd and sd >= 3 and _smooth(v, r, sd, noisy) and max(Counter(v).values()) <= 0.2 * len(v)
                  and len({(v[j + 1] - v[j]) for j in range(len(v) - 1)}) >= 8
                  and (sd < 512 or _block_stats([x & 255 for x in v])[0] >= 0.8)):     # low bytes of loud 16-bit audio are noise
                ok += 1
                wave += 1
                s1 = sum(map(abs, map(operator.sub, v[1:], v)))
                s2 = sum(map(abs, map(operator.sub, v[2:], v)))
                stereo += s1 > 1.5 * s2
                lo, hi = min(lo, min(v)), max(hi, max(v))
            else:
                fail += 1
        if ok >= 0.75 * len(pos) and wave >= 0.4 * len(pos):
            ch = "interleaved stereo (every second sample is smoother)" if stereo >= 0.6 * wave else "mono or unknown channels"
            return (f"sample stream: 16-bit little-endian PCM-like waveform ({lo}..{hi}, {ch}, sample phase {phase}, "
                    f"neighbouring samples smooth), no records; rate comes from the container header")
    return None


def sample_stream(d: bytes) -> str | None:
    """Text of the 'sample stream, no records' verdict when the data is a smooth 8-bit or 16-bit waveform."""
    n = len(d)
    if n < 4 * STREAM_BLOCK:
        return None
    if sum(32 <= x < 127 for x in d[:8192]) > 0.85 * len(d[:8192]) or _is_text(d[:8192]):
        return None                 # text and digits are smooth too
    blocks = [d[i:i + STREAM_BLOCK] for i in range(0, n - STREAM_BLOCK + 1, STREAM_BLOCK)]
    step = max(1, len(blocks) // 48)
    sel = blocks[::step]
    # clean waveforms before noisy ones
    return (_stream8(d, sel, False) or _stream16(d, n, False) or _stream8(d, sel, True) or _stream16(d, n, True))
